//! The `pubky-switch` binary: runs the Pubky Switch service.

use std::{path::PathBuf, process::ExitCode, sync::Arc};

use clap::{Parser, Subcommand};
use pubky_switch::{
    admin::{self, AdminState},
    changes::ChangeListener,
    check_marks::{self, CheckOptions},
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
    /// Compare every account's chain head with its service key's mark, reading only:
    /// prints JSON lines, and exits 2 when an account needs attention.
    CheckMarks {
        /// Read this database instead of the configured one, against the same key store.
        /// Prefer the variable when the URL holds a password: a command line is visible to
        /// other users of the host.
        #[arg(long, env = "PUBKY_SWITCH_REPLICA_URL", hide_env_values = true)]
        replica: Option<String>,
        /// Report every account, not only those that need attention.
        #[arg(long)]
        all: bool,
    },
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
        Command::CheckMarks { replica, all } => {
            check_marks_command(&config, replica.as_deref(), all)
        }
        Command::Run => run(config),
    }
}

fn check_marks_command(config: &Config, replica: Option<&str>, all: bool) -> ExitCode {
    let runtime = match tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
    {
        Ok(runtime) => runtime,
        Err(error) => {
            eprintln!("pubky-switch: check-marks: starting the runtime: {error}");
            return ExitCode::FAILURE;
        }
    };
    let report = CheckOptions::from_config(config, replica, all)
        .and_then(|options| runtime.block_on(check_marks::run(&options)))
        .and_then(|report| Ok((report.to_json_lines()?, report.needs_attention())));
    match report {
        Ok((text, attention)) => {
            print!("{text}");
            if attention {
                ExitCode::from(2)
            } else {
                ExitCode::SUCCESS
            }
        }
        Err(error) => {
            eprintln!("pubky-switch: check-marks: {error}");
            ExitCode::FAILURE
        }
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
    // One process serves a key store and a database (docs/configuration.md, "Topology"):
    // a second one refuses to start here, before it opens the key store, migrates or
    // serves anything.
    let _key_dir_lock = FileKeyStore::lock_dir(&key_dir)?;
    let keys = FileKeyStore::open(&key_dir)?;
    let store = Store::connect(&config.database).await?;
    let instance = store
        .hold_instance_lock(pubky_switch::store::LockTiming::SERVICE)
        .await?;
    // The database's lock lives with its session: once another session holds it, or it
    // can't be confirmed, this one stops (docs/configuration.md, "Topology").
    tokio::spawn(async move {
        let lost = instance.keep().await;
        tracing::error!(failure = %lost, "the instance lock: stopping");
        std::process::exit(1);
    });
    if config.database.migrate_on_start {
        store.migrate().await?;
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
            // Keys an erasure left owed, by a key store failure or a crash, go first (Switch
            // wire 7.4.16), then accounts a restored database brought back after their
            // erasure (spec 6.5), before the API listener takes a request.
            let service = Arc::new(
                Service::new(
                    origin.clone(),
                    store.clone(),
                    Arc::new(keys.clone()),
                    time.clone(),
                    config.limits.clone(),
                )
                .with_push(config.push.enabled)
                .with_push_concurrency(config.push.concurrency)
                .with_backup_retention_days(config.keys.backup_retention_days)
                .started()
                .await,
            );
            // Webhooks queued by any instance are sent by one of them (Switch wire 8.2).
            if config.push.enabled {
                tokio::spawn(
                    service
                        .clone()
                        .deliver_pushes_until(until_stopped(stopped.clone())),
                );
            }
            // Changes made by any instance wake the feed reads waiting here.
            let changes = ChangeListener::connect(&store).await?;
            tokio::spawn(changes.run(service.changes(), until_stopped(stopped.clone())));
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
