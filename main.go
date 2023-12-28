package main

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/alecthomas/kingpin/v2"
	"github.com/altinity/clickhouse-operator/pkg/apis/metrics"
	"github.com/altinity/clickhouse-operator/pkg/model/clickhouse"
	"github.com/prometheus/common/version"
	"github.com/sirupsen/logrus"
)

const (
	defaultNamespace = "default"

	defaultMetricsEndpoint = ":8888"
	defaultChiListEP       = ":8888"

	defaultChScheme       = "http"
	defaultChHost         = "127.0.0.1"
	defaultChUser         = "default"
	defaultChPass         = ""
	defaultChPort         = "8123"
	defaultChRootCA       = ""
	defaultTimeoutConnect = "2s"
	defaultTimeoutQuery   = "5s"

	metricsPath = "/metrics"
	chiListPath = "/chi"
)

var (
	scheme         string
	username       string
	password       string
	port           int
	namespace      string
	chiName        string
	hostnames      []string
	rootCA         string
	connectTimeout time.Duration
	queryTimeout   time.Duration

	metricsEP string
	chiListEP string

	log       = logrus.New()
	logLevel  string
	logFormat string
)

func init() {
	host, _ := os.Hostname()
	kingpin.Flag("chi-name", "Clickhouse cluster name or $HOSTNAME.").
		Default(host).Envar("HOSTNAME").StringVar(&chiName)
	kingpin.Flag("namespace", "The namespace label for metrics or $NAMESPACE.").
		Default(defaultNamespace).Envar("NAMESPACE").StringVar(&namespace)
	kingpin.Flag("metrics-endpoint", "The Prometheus exporter endpoint.").
		Default(defaultMetricsEndpoint).StringVar(&metricsEP)
	kingpin.Flag("chi-list-endpoint", "The CHI list endpoint.").
		Default(defaultChiListEP).StringVar(&chiListEP)
	kingpin.Flag("scheme", "Clickhouse HTTP scheme or $CH_SCHEME").
		Default(defaultChScheme).Envar("CH_SCHEME").EnumVar(&scheme, "http", "https")
	kingpin.Flag("username", "Clickhouse username or $CH_USERNAME.").
		Default(defaultChUser).Envar("CH_USERNAME").StringVar(&username)
	kingpin.Flag("password", "Clickhouse user password or $CH_PASSWORD.").
		Default(defaultChPass).Envar("CH_PASSWORD").StringVar(&password)
	kingpin.Flag("port", "Clickhouse HTTP port number or $CH_PORT.").
		Default(defaultChPort).Envar("CH_PORT").IntVar(&port)
	kingpin.Flag("address", "A list of Clickhouse hosts").
		Default(defaultChHost).StringsVar(&hostnames)
	kingpin.Flag("root-ca", "Path to root CA").
		Default(defaultChRootCA).Envar("CH_ROOT_CA").StringVar(&rootCA)
	kingpin.Flag("connect-timeout", "").
		Default(defaultTimeoutConnect).
		Envar("CH_CONNECT_TIMEOUT").DurationVar(&connectTimeout)
	kingpin.Flag("query-timeout", "").
		Default(defaultTimeoutQuery).
		Envar("CH_QUERY_TIMEOUT").DurationVar(&queryTimeout)
	kingpin.Flag("log-level",
		"Only log messages with the given severity or above. Valid levels: [debug, info, warn, error, fatal]",
	).Default("info").EnumVar(&logLevel, "debug", "info", "warn", "error", "fatal")
	kingpin.Flag("log-format",
		"Set the log format. Valid formats: [json, text]",
	).Default("json").EnumVar(&logFormat, "json", "text")

	kingpin.Version(version.Print("clickhouse-exporter"))
	kingpin.HelpFlag.Short('h')

	kingpin.Parse()
}

func main() {
	if err := setLogLevel(logLevel); err != nil {
		log.Fatal(err)
	}
	if err := setLogFormat(logFormat); err != nil {
		log.Fatal(err)
	}

	ctx, cancelFunc := context.WithCancel(context.Background())
	stopChan := make(chan os.Signal, 2)
	signal.Notify(stopChan, os.Interrupt, syscall.SIGTERM)
	go func() {
		<-stopChan
		cancelFunc()
		<-stopChan
		os.Exit(1)
	}()

	log.Infof("Starting metrics exporter %s", version.Info())
	log.Infof("Build context %s", version.BuildContext())

	params := clickhouse.NewClusterConnectionParams(
		scheme,
		username,
		password,
		rootCA,
		port,
	)
	params.SetConnectTimeout(connectTimeout)
	params.SetQueryTimeout(queryTimeout)

	metrics.StartMetricsREST(
		params,

		metricsEP,
		metricsPath,

		chiListEP,
		chiListPath,
	).UpdateWatch(namespace, chiName, hostnames)

	<-ctx.Done()
}

func setLogLevel(level string) error {
	lvl, err := logrus.ParseLevel(level)
	if err != nil {
		return err
	}
	log.SetLevel(lvl)

	return nil
}

func setLogFormat(format string) error {
	var formatter logrus.Formatter

	switch format {
	case "text":
		formatter = &logrus.TextFormatter{
			DisableColors: true,
			FullTimestamp: true,
		}
	case "json":
		formatter = &logrus.JSONFormatter{}
	default:
		return fmt.Errorf("invalid log format: %s", format)
	}

	log.SetFormatter(formatter)

	return nil
}
