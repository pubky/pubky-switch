//! The `pubky-switch` binary: runs the Pubky Switch service.

use std::{path::PathBuf, process::ExitCode, sync::Arc};

use clap::{Parser, Subcommand};
use pubky_switch::{
    admin::{self, AdminState},
    config::Config,
    http,
    keys::{FileKeyStore, KeyStoreReadiness},
    service::Service,
    store::{Store, StoreReadiness},
    telemetry,
    time::{SystemClock, TrustedTime, roughtime::RoughtimeSource},
};

/// Inbox and coordination service for Pubky identities.
#[derive(Debug, Parser)]
#[command(version, about)]
struct Cli {
    /// The configuration file. Without one, every setting takes its default.
    #[arg(long, short, env = "PUBKY_SWITCH_CONFIG", global = true)]
    config: Option<PathBuf>,

    #[command(subcommand)]
    command: Option<Command>,
}

#[derive(Debug, Subcommand)]
enum Command {
    /// Run the service (the default).
    Run,
    /// Check the configuration, and print it with every default written out.
    CheckConfig,
}

fn main() -> ExitCode {
    let cli = Cli::parse();
    let config = match &cli.config {
        Some(path) => Config::load(path),
        None => Ok(Config::default()),
    };
    let config = match config {
        Ok(config) => config,
        Err(error) => {
            eprintln!("pubky-switch: {error}");
            return ExitCode::FAILURE;
        }
    };
    match cli.command.unwrap_or(Command::Run) {
        Command::CheckConfig => match config.to_toml() {
            Ok(text) => {
                print!("{text}");
                ExitCode::SUCCESS
            }
            Err(error) => {
                eprintln!("pubky-switch: writing the configuration: {error}");
                ExitCode::FAILURE
            }
        },
        Command::Run => run(config),
    }
}

fn run(config: Config) -> ExitCode {
    if let Err(error) = telemetry::init_logs(&config.log) {
        eprintln!("pubky-switch: {error}");
        return ExitCode::FAILURE;
    }
    let runtime = match tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
    {
        Ok(runtime) => runtime,
        Err(error) => {
            tracing::error!(%error, "starting the runtime");
            return ExitCode::FAILURE;
        }
    };
    match runtime.block_on(serve(config)) {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            tracing::error!(error = %error, "the service stopped");
            ExitCode::FAILURE
        }
    }
}

async fn serve(config: Config) -> Result<(), Box<dyn std::error::Error>> {
    let metrics = telemetry::init_metrics()?;
    let time = Arc::new(TrustedTime::new(
        config.trusted_time.clone(),
        Arc::new(SystemClock),
    ));
    let (stop, stopped) = tokio::sync::watch::channel(false);
    let source = RoughtimeSource::new(&config.trusted_time.roughtime)
        .map_err(|(name, reason)| format!("trusted_time.{name}: {reason}"))?;
    if !config.trusted_time.required {
        tracing::warn!("trusted time is not required: the wall clock is taken as trusted");
    } else if let Some(source) = source {
        let mut stopped = stopped.clone();
        tokio::spawn(time.clone().run_sampler(Arc::new(source), async move {
            let _ = stopped.wait_for(|stop| *stop).await;
        }));
        tracing::info!(
            servers = config.trusted_time.roughtime.servers.len(),
            "sampling trusted time from roughtime"
        );
    } else {
        tracing::warn!(
            "no time source is configured: the service has no trusted time, and refuses what \
             depends on its time"
        );
    }
    time.record_gauges();

    let key_dir = config
        .keys
        .path
        .clone()
        .ok_or("no key store: set keys.path")?;
    let keys = FileKeyStore::open(&key_dir)?;
    let store = Store::connect(&config.database).await?;
    if config.database.migrate_on_start {
        store
            .migrate(&pubky_switch::service::announced_limits(&config.limits))
            .await?;
        tracing::info!("database schema up to date");
    }

    // Ctrl-C or SIGTERM stops every listener and the time sampler.
    tokio::spawn(async move {
        shutdown_signal().await;
        let _ = stop.send(true);
    });
    let until_stopped = |mut stopped: tokio::sync::watch::Receiver<bool>| async move {
        let _ = stopped.wait_for(|stop| *stop).await;
    };

    let api = match config.server.origin.clone() {
        Some(origin) => {
            let service = Arc::new(Service::new(
                origin.clone(),
                store.clone(),
                Arc::new(keys.clone()),
                time.clone(),
                config.limits.clone(),
            ));
            let router = http::router(service, config.server.proxy.clone());
            let listener = tokio::net::TcpListener::bind(config.server.listen).await?;
            tracing::info!(api = %listener.local_addr()?, %origin, "serving the API");
            Some(tokio::spawn(http::serve(
                listener,
                router,
                until_stopped(stopped.clone()),
            )))
        }
        None => {
            tracing::warn!("no server.origin: the API listener is off");
            None
        }
    };

    let admin_state = AdminState::new(time, Some(metrics))
        .with_check(Arc::new(StoreReadiness(store.clone())))
        .with_check(Arc::new(KeyStoreReadiness(keys.clone())));
    let admin = admin::router(admin_state);
    let listener = tokio::net::TcpListener::bind(config.admin.listen).await?;
    tracing::info!(
        admin = %listener.local_addr()?,
        version = env!("CARGO_PKG_VERSION"),
        "pubky-switch started"
    );
    axum::serve(listener, admin)
        .with_graceful_shutdown(until_stopped(stopped.clone()))
        .await?;
    if let Some(api) = api {
        api.await??;
    }
    drop(stopped);
    store.close().await;
    tracing::info!("pubky-switch stopped");
    Ok(())
}

/// Resolves on Ctrl-C or, on Unix, SIGTERM.
async fn shutdown_signal() {
    let interrupt = async {
        if let Err(error) = tokio::signal::ctrl_c().await {
            tracing::error!(%error, "listening for Ctrl-C");
            std::future::pending::<()>().await;
        }
    };
    #[cfg(unix)]
    let terminate = async {
        match tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate()) {
            Ok(mut signal) => {
                signal.recv().await;
            }
            Err(error) => {
                tracing::error!(%error, "listening for SIGTERM");
                std::future::pending::<()>().await;
            }
        }
    };
    #[cfg(not(unix))]
    let terminate = std::future::pending::<()>();
    tokio::select! {
        () = interrupt => {}
        () = terminate => {}
    }
    tracing::info!("shutting down");
}
