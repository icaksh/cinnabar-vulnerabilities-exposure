package db

import (
	"context"
	"hash/fnv"
)

func SourceLockKey(source string) int64 {
	h := fnv.New64a()
	_, _ = h.Write([]byte(source))
	return int64(h.Sum64())
}

func (d *DB) TryAdvisoryLock(ctx context.Context, key int64) (func(), bool, error) {
	conn, err := d.pool.Acquire(ctx)
	if err != nil {
		return nil, false, err
	}
	var got bool
	if err := conn.QueryRow(ctx, `SELECT pg_try_advisory_lock($1)`, key).Scan(&got); err != nil {
		conn.Release()
		return nil, false, err
	}
	if !got {
		conn.Release()
		return nil, false, nil
	}
	release := func() {
		_, _ = conn.Exec(context.Background(), `SELECT pg_advisory_unlock($1)`, key)
		conn.Release()
	}
	return release, true, nil
}
