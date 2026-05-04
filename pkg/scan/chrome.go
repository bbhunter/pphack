/*
pphack - Advanced Client-Side Prototype Pollution Scanner

This repository is under MIT License https://github.com/edoardottt/pphack/blob/main/LICENSE
*/

package scan

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/chromedp/cdproto/network"
	"github.com/chromedp/chromedp"
	"github.com/edoardottt/pphack/pkg/exploit"
	"github.com/edoardottt/pphack/pkg/output"
	"github.com/projectdiscovery/gologger"
)

// GetChromeOptions takes as input the runner settings and returns
// the chrome options used to configure the headless browser instance.
// It always disables certificate errors and sets a custom user agent.
// If a proxy is configured in the runner options, it is appended as well.
func GetChromeOptions(r *Runner) []func(*chromedp.ExecAllocator) {
	copts := append(chromedp.DefaultExecAllocatorOptions[:],
		chromedp.Flag("ignore-certificate-errors", true),
		chromedp.UserAgent(r.UserAgent),
	)

	if r.Options.Proxy != "" {
		copts = append(copts, chromedp.ProxyServer(r.Options.Proxy))
	}

	return copts
}

// GetChromeBrowser takes as input the chrome options and returns
// the context with the associated cancel functions to use the
// headless chrome browser it creates.
// Returns ecancel (exec allocator cancel), pctx (parent browser context),
// and pcancel (parent context cancel).
// Callers must invoke pcancel before ecancel to ensure correct cleanup order.
// ecancel is also called internally on fatal browser startup failure
// to avoid leaking the exec allocator before the process exits.
func GetChromeBrowser(copts []func(*chromedp.ExecAllocator)) (context.CancelFunc, context.Context, context.CancelFunc) {
	ectx, ecancel := chromedp.NewExecAllocator(context.Background(), copts...)
	pctx, pcancel := chromedp.NewContext(ectx)

	// Run an empty chromedp task to verify the browser starts successfully.
	if err := chromedp.Run(pctx); err != nil {
		ecancel()
		gologger.Fatal().Msgf("error starting browser: %s", err.Error())
	}

	return ecancel, pctx, pcancel
}

// buildHeaders is a helper that converts a headers map into a chromedp.Tasks
// slice containing the SetExtraHTTPHeaders action.
// Returns nil if headers is nil, making it safe to append directly onto any
// existing chromedp.Tasks without an extra nil check at the call site.
func buildHeaders(headers map[string]interface{}) chromedp.Tasks {
	if headers == nil {
		return nil
	}

	return chromedp.Tasks{network.SetExtraHTTPHeaders(network.Headers(headers))}
}

// Scan is the core function that performs the prototype pollution scan.
// It takes a parent browser context (pctx), runner config (r), optional HTTP
// headers, the JavaScript payload (js), the original input value and the
// fully constructed target URL.
//
// Flow:
//  1. Creates a timeout-scoped context and a dedicated Chrome tab context.
//  2. Navigates to targetURL and evaluates the JS pollution payload.
//  3. If exploit mode is enabled and the payload returned a non-empty result,
//     it runs fingerprinting to identify the affected library/sink.
//  4. Attempts exploitation using the fingerprint results.
//  5. Populates and returns a ResultData struct with all findings and errors.
func Scan(
	pctx context.Context,
	r *Runner,
	headers map[string]interface{},
	js, value, targetURL string,
) (output.ResultData, error) {
	var (
		resScan      string
		resDetection []string
	)

	resultData := output.ResultData{
		TargetURL: value,
		ScanURL:   targetURL,
	}

	// Wrap the parent context with a per-scan timeout to avoid blocking.
	ctx, ctxCancel := context.WithTimeout(pctx, time.Second*time.Duration(r.Options.Timeout))
	defer ctxCancel()

	// Open a new Chrome tab scoped to the timeout context.
	// tabCancel explicitly closes the tab when Scan returns
	// preventing tab accumulation across concurrent scans.
	tabCtx, tabCancel := chromedp.NewContext(ctx)
	defer tabCancel()

	// Build the scan task list: optionally inject custom HTTP headers,
	// navigate to the target, then evaluate the prototype pollution JS payload.
	scanTasks := buildHeaders(headers)
	scanTasks = append(
		scanTasks,
		chromedp.Navigate(targetURL),
		chromedp.EvaluateAsDevTools(js, &resScan),
	)

	// Execute the scan tasks inside the dedicated tab context.
	errScan := chromedp.Run(tabCtx, scanTasks)
	if errScan != nil {
		resultData.ScanError = errScan.Error()
	}

	resultData.JSEvaluation = strings.TrimSpace(resScan)

	if !r.Options.Exploit || errScan != nil || resultData.JSEvaluation == "" {
		return resultData, nil
	}

	if r.Options.Verbose {
		gologger.Info().Label("VULN").Msg(fmt.Sprintf("Target is Vulnerable %s", targetURL))
	}

	// Run fingerprinting as a separate, isolated task list.
	fingerprintTasks := chromedp.Tasks{
		chromedp.EvaluateAsDevTools(exploit.Fingerprint, &resDetection),
	}

	errDetection := chromedp.Run(tabCtx, fingerprintTasks)
	if errDetection != nil {
		gologger.Error().Msg(errDetection.Error())
		resultData.FingerprintError = errDetection.Error()
	}

	// Store fingerprint results and cross-reference known exploit references.
	resultData.Fingerprint = resDetection
	resultData.References = exploit.GetReferences(resDetection)

	if r.Options.Verbose {
		gologger.Info().Msg(fmt.Sprintf("Trying to exploit %s", value))
	}

	exploitTasks := buildHeaders(headers)

	result, errExploit := exploit.CheckExploit(
		pctx,
		exploitTasks,
		resDetection,
		targetURL,
		r.Options.Verbose,
		r.Options.Timeout,
	)

	resultData.ExploitURLs = result

	if errExploit != nil {
		resultData.ExploitError = errExploit.Error()
		gologger.Error().Msg(errExploit.Error())
	}

	return resultData, nil
}
