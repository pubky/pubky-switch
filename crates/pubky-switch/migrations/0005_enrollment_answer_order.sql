-- Enrollment answers drop in the order they were kept, and the answer to the enrollment
-- that created the account is never dropped: the same enrollment again always gets the
-- same answer (Switch wire 3.7, 9.1).
ALTER TABLE enrollment_answers
    -- The order answers were kept in; the oldest drops first.
    ADD COLUMN kept_order BIGINT GENERATED ALWAYS AS IDENTITY,
    -- The answer to the enrollment that created the account.
    ADD COLUMN creating BOOLEAN NOT NULL DEFAULT false;

-- An account's creating enrollment was answered at its creation, with its first key.
UPDATE enrollment_answers e SET creating = true
    FROM accounts a
    WHERE a.id = e.account_id AND e.answered_at_ms = a.created_at_ms
      AND e.service_key = a.service_key
      AND e.enrollment_hash = (
          SELECT f.enrollment_hash FROM enrollment_answers f
          WHERE f.account_id = a.id AND f.answered_at_ms = a.created_at_ms
            AND f.service_key = a.service_key
          ORDER BY f.enrollment_hash LIMIT 1
      );
CREATE UNIQUE INDEX enrollment_answers_one_creating ON enrollment_answers (account_id)
    WHERE creating;
