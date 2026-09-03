use criterion::{BenchmarkId, Criterion, Throughput, criterion_group, criterion_main};
use sql_fingerprint::fingerprint;
use std::hint::black_box;

const ONE_MIB: usize = 1024 * 1024;

fn multi_value_insert(minimum_len: usize) -> String {
    let mut query = String::with_capacity(minimum_len);
    query.push_str("INSERT INTO events (user_id, payload) VALUES ");

    let row = "(123, 'sample payload'),";
    while query.len() + row.len() < minimum_len {
        query.push_str(row);
    }
    query.push_str("(123, 'sample payload')");

    query
}

fn repeated_union(count: usize) -> String {
    (0..count)
        .map(|_| "SELECT id FROM users WHERE active = true")
        .collect::<Vec<_>>()
        .join(" UNION ")
}

fn alphabetic_identifier(mut value: usize) -> String {
    let mut suffix = [b'a'; 4];
    for character in suffix.iter_mut().rev() {
        *character += (value % 26) as u8;
        value /= 26;
    }

    String::from_utf8(suffix.to_vec()).expect("alphabetic identifier must be valid UTF-8")
}

fn non_repeated_union(count: usize) -> String {
    // Alphabetic suffixes remain distinct after numeric literal normalization.
    (0..count)
        .map(|index| {
            let identifier = alphabetic_identifier(index);
            format!("SELECT item_{identifier} FROM source_{identifier}")
        })
        .collect::<Vec<_>>()
        .join(" UNION ")
}

fn long_block_comment(payload_len: usize) -> String {
    format!("SELECT 1 /* {} */ FROM users", "x".repeat(payload_len))
}

fn long_unclosed_string(payload_len: usize) -> String {
    format!("SELECT '{}", "x".repeat(payload_len))
}

fn benchmark_fingerprint(criterion: &mut Criterion) {
    let cases = [
        (
            "typical_select",
            "SELECT u.id, u.email FROM users u WHERE u.tenant_id = 42 \
             AND u.status IN ('active', 'pending') ORDER BY u.id ASC LIMIT 100"
                .to_string(),
        ),
        ("multi_value_insert_1_mib", multi_value_insert(ONE_MIB)),
        ("repeated_union_1000", repeated_union(1000)),
        ("block_comment_1_mib", long_block_comment(ONE_MIB)),
        ("unclosed_string_1_mib", long_unclosed_string(ONE_MIB)),
    ];

    let mut group = criterion.benchmark_group("fingerprint");

    for (name, query) in &cases {
        group.throughput(Throughput::Bytes(query.len() as u64));
        group.bench_with_input(
            BenchmarkId::new(*name, query.len()),
            query,
            |bencher, query| {
                bencher.iter(|| black_box(fingerprint(black_box(query.as_str()))));
            },
        );
    }

    group.finish();
}

fn benchmark_non_repeated_union(criterion: &mut Criterion) {
    let mut group = criterion.benchmark_group("non_repeated_union");
    group.sample_size(10);

    for count in [2_000, 4_000, 8_000] {
        let query = non_repeated_union(count);
        group.throughput(Throughput::Elements(count as u64));
        group.bench_with_input(
            BenchmarkId::from_parameter(count),
            &query,
            |bencher, query| {
                bencher.iter(|| black_box(fingerprint(black_box(query.as_str()))));
            },
        );
    }

    group.finish();
}

criterion_group!(benches, benchmark_fingerprint, benchmark_non_repeated_union);
criterion_main!(benches);
