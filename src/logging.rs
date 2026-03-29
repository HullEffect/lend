use tracing_subscriber::EnvFilter;

const DEFAULT_LOG_FILTER: &str = "warn,lend=info,noq_proto::connection=error";

pub(crate) fn init() {
    let env_filter = if std::env::var_os(EnvFilter::DEFAULT_ENV).is_some() {
        EnvFilter::try_from_default_env()
            .unwrap_or_else(|_| EnvFilter::new(DEFAULT_LOG_FILTER))
    } else {
        EnvFilter::new(DEFAULT_LOG_FILTER)
    };

    tracing_subscriber::fmt()
        .with_env_filter(env_filter)
        .with_target(false)
        .without_time()
        .compact()
        .with_writer(std::io::stderr)
        .init();
}
