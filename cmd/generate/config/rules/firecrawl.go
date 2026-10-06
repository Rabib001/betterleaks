package rules

import (
	"github.com/betterleaks/betterleaks/v2/cmd/generate/config/utils"
	"github.com/betterleaks/betterleaks/v2/cmd/generate/secrets"
	"github.com/betterleaks/betterleaks/v2/config"
)

// https://docs.firecrawl.dev/api-reference/endpoint/credit-usage
// Keys are "fc-" followed by a dashless UUID; the API itself checks ^fc-[0-9a-f]{32}$.
// The endpoint is read-only and does not consume credits.
const firecrawlValidateExpr = `let r = http.get("https://api.firecrawl.dev/v2/team/credit-usage", {
  "Authorization": "Bearer " + finding["secret"],
  "Accept": "application/json"
});
r.status == 200 && r.json?.success == true ? {
  "result": "valid"
} : r.status == 401 ? {
  "result": "invalid", "reason": "Unauthorized"
} : validate.unknown(r)`

func FirecrawlAPIKey() *config.Rule {
	r := config.Rule{
		ID:           "firecrawl-api-key",
		Confidence:   "high",
		Description:  "Detected a Firecrawl API Key, which may expose web scraping and crawling services and account credits to unauthorized use.",
		Regex:        utils.GenerateUniqueTokenRegex(`fc-`+utils.Hex("32"), true),
		Keywords:     []string{"fc-"},
		ValidateExpr: firecrawlValidateExpr,
		// 32 hex chars is short: <= 3.5 would drop ~4% of real keys, <= 3.0 drops none
		// while still rejecting repeated placeholders such as fc-000... or fc-deadbeef...
		FilterExpr: `entropy(finding["secret"]) <= 3.0`,
	}

	tps := utils.GenerateSampleSecrets("firecrawl", "fc-"+secrets.NewSecretWithEntropy(utils.Hex("32"), 3.5))
	tps = append(tps,
		`app = FirecrawlApp(api_key="fc-384694d8124e473a977b88a305cf7a3b")`,
	)
	fps := []string{
		// Too short
		`FIRECRAWL_API_KEY=fc-384694d8124e473a977b88a305cf7a3`,
		// Too long
		`FIRECRAWL_API_KEY=fc-384694d8124e473a977b88a305cf7a3b384694d8`,
		// Documentation placeholder
		`FIRECRAWL_API_KEY=fc-YOUR_API_KEY`,
		// Low entropy
		`FIRECRAWL_API_KEY=fc-00000000000000000000000000000000`,
		`FIRECRAWL_API_KEY=fc-deadbeefdeadbeefdeadbeefdeadbeef`,
	}
	return utils.Validate(r, tps, fps)
}
