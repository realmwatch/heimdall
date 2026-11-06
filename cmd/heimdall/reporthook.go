// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/realmwatch/heimdall/internal/config"
	"github.com/realmwatch/heimdall/internal/netx"
	"github.com/realmwatch/heimdall/internal/notify"
	"github.com/realmwatch/heimdall/internal/store"
)

// The report webhook's signing secret: systemd credential
// heimdall-report-webhook, stored by `heimdall report-webhook set`.
const reportHookCredential = "heimdall-report-webhook"

// defaultReportHookFile is where `report-webhook set` stores the secret. A
// seam for tests.
var defaultReportHookFile = "/etc/heimdall/report-webhook-secret"

// reportHookHTTPClient builds the webhook's client: HTTPS to its URL's
// host only. A seam for tests.
var reportHookHTTPClient = func(host string) *http.Client {
	return netx.New([]string{host}, "heimdall/"+version).HTTPClient()
}

// reportHook builds the report webhook from [report_webhook] and its
// stored secret; nil when it's off. With fallback (the CLI as root), the
// default secret file is read directly.
func reportHook(cfg config.Config, fallback bool) (*notify.ReportHook, error) {
	raw := cfg.ReportWebhook.URL
	if raw == "" {
		return nil, nil
	}
	file := ""
	if fallback {
		file = defaultReportHookFile
	}
	secret, _, err := credentialFile(reportHookCredential, file)
	if err != nil {
		return nil, fmt.Errorf("report webhook: %w (store it with `sudo heimdall report-webhook set <url>`)", err)
	}
	u, err := url.Parse(raw)
	if err != nil {
		return nil, err
	}
	return &notify.ReportHook{URL: raw, Secret: []byte(secret), Retry: notifyRetry,
		Client: reportHookHTTPClient(strings.ToLower(u.Hostname()))}, nil
}

// reportEvents sends report.received events from one goroutine, so ingest
// never waits on the receiver. A full queue drops the event: the receiver
// is told to poll as well, so a missed event only delays it.
type reportEvents struct {
	hook  *notify.ReportHook
	queue chan notify.ReportEvent
	log   *slog.Logger
}

// startReportHook starts the report webhook, or returns nil when it's off
// (Notify on nil does nothing).
func startReportHook(ctx context.Context, cfg config.Config, log *slog.Logger) *reportEvents {
	hook, err := reportHook(cfg, false)
	if err != nil {
		log.Warn("report webhook off", "err", err)
		return nil
	}
	if hook == nil {
		return nil
	}
	r := &reportEvents{hook: hook, queue: make(chan notify.ReportEvent, 256), log: log.With("component", "report-webhook")}
	go func() {
		for {
			select {
			case <-ctx.Done():
				return
			case ev := <-r.queue:
				if err := r.hook.Send(ctx, ev); err != nil {
					r.log.Warn("report event not delivered", "host", ev.Host, "err", err)
				}
			}
		}
	}()
	return r
}

// Notify queues a report.received event for a host's accepted report.
func (r *reportEvents) Notify(host store.IngestHost, snapshotID int64, changed bool) {
	if r == nil {
		return
	}
	ev := notify.ReportEvent{Event: "report.received", Delivery: notify.NewDelivery(), Org: host.OrgSlug, Host: host.Name,
		SnapshotID: snapshotID, Changed: changed, ReceivedAt: time.Now().UTC()}
	select {
	case r.queue <- ev:
	default:
		r.log.Warn("report event dropped: queue full", "host", host.Name)
	}
}

func cmdReportWebhookSet(a *app, args []string) error {
	fs := a.flags("report-webhook set", "<https-url> [--secret-stdin] [--file path] [--unit path]")
	path := fs.String("file", defaultReportHookFile, "where to store the signing secret (the unit's LoadCredential source)")
	fromStdin := fs.Bool("secret-stdin", false, "read the signing secret from stdin instead of generating one")
	unitFile := fs.String("unit", hubUnitFile, "the hub's systemd unit (gets the LoadCredential line)")
	rest, err := parse(fs, args, 1)
	if err != nil {
		return err
	}
	raw := strings.TrimSpace(rest[0])
	if err := (config.Config{ReportWebhook: config.ReportWebhook{URL: raw}}).Validate(); err != nil {
		// Validate checks the whole config; only the webhook's errors matter here.
		for _, e := range strings.Split(err.Error(), "\n") {
			if strings.HasPrefix(e, "report_webhook.") {
				return errors.New(e)
			}
		}
	}
	var secret string
	generated := false
	if *fromStdin {
		b, err := io.ReadAll(io.LimitReader(a.stdin, 4097))
		if err != nil {
			return err
		}
		secret = strings.TrimSpace(string(b))
		if len(secret) < 32 || len(secret) > 4096 || strings.ContainsFunc(secret, func(r rune) bool { return r <= ' ' || r == 0x7f }) {
			return errors.New("the secret must be 32 to 4096 printable characters with no spaces")
		}
	} else {
		b := make([]byte, 32)
		if _, err := rand.Read(b); err != nil {
			return err
		}
		secret, generated = hex.EncodeToString(b), true
	}
	if err := writePrivate(*path, secret+"\n"); err != nil {
		return err
	}
	fmt.Fprintf(a.stderr, "Stored the report webhook's signing secret in %s (owner-only).\n", *path)
	if *path == defaultReportHookFile || *unitFile != hubUnitFile {
		changed, err := enableCredential(*unitFile, reportHookCredential, *path)
		switch {
		case err != nil:
			fmt.Fprintf(a.stderr, "Couldn't update the unit (%v).\nAdd `LoadCredential=%s:%s` to it yourself.\n", err, reportHookCredential, *path)
		case changed:
			fmt.Fprintf(a.stderr, "Added LoadCredential=%s to %s.\n", reportHookCredential, *unitFile)
			if *unitFile == hubUnitFile {
				if err := systemctl(a, "daemon-reload"); err != nil {
					fmt.Fprintf(a.stderr, "systemctl daemon-reload failed: %v\n", err)
				}
			}
		}
	}
	cfgPath := hubConfigPath(a.configPath)
	if err := updateConfigKeys(cfgPath, "report_webhook", [][2]string{{"url", fmt.Sprintf("%q", raw)}},
		func(c config.Config) bool { return c.ReportWebhook.URL == raw }); err != nil {
		fmt.Fprintf(a.stderr, "Couldn't update %s (%v).\nSet url = %q under [report_webhook] yourself.\n", cfgPath, err, raw)
	} else {
		fmt.Fprintf(a.stderr, "Set [report_webhook] url in %s.\n", cfgPath)
	}
	if generated {
		// The receiver needs it to check signatures; this is the only time it's shown.
		fmt.Fprintln(a.stderr, "Give the receiver this signing secret (shown once):")
		fmt.Fprintln(a.stdout, secret)
	}
	fmt.Fprintln(a.stderr, "Apply with `sudo heimdall restart`, then check it with `sudo heimdall report-webhook test`.")
	return nil
}

func cmdReportWebhookTest(a *app, args []string) error {
	if _, err := parse(a.flags("report-webhook test", ""), args, 0); err != nil {
		return err
	}
	cfg, err := config.Load(hubConfigPath(a.configPath))
	if err != nil {
		return err
	}
	hook, err := reportHook(cfg, isRoot())
	if err != nil {
		return err
	}
	if hook == nil {
		return errors.New("the report webhook is off: run `sudo heimdall report-webhook set <url>`")
	}
	ev := notify.ReportEvent{Event: "test", Delivery: notify.NewDelivery(), ReceivedAt: time.Now().UTC()}
	if err := hook.Send(a.ctx, ev); err != nil {
		return err
	}
	fmt.Fprintf(a.stderr, "Sent a signed test event to %s.\n", notify.RedactURL(hook.URL))
	return nil
}
