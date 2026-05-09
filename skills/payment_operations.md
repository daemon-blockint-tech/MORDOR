# MORDOR Skill: Payment Operations

Agent: **PAY** — programmable money operations for the pipeline.
Tool: `pay` CLI (v0.16.0) at `${PAY_BIN_PATH}`.
MCP: `pay mcp` server registered in `mcp_config/claude_desktop_config.json`.

Use for stablecoin payments, account management, API monetization, and
ransomware payment tracing across the analysis pipeline.

## Pipeline Integration

| Phase | Use Case | PAY Action |
|-------|----------|------------|
| 1 — Fingerprint | Ransom note address extraction | `skills_search` for known ransom wallets |
| 2 — Filter | Flag payment-related IOCs | `balance_check` for suspicious balances |
| 4 — Map | Trace on-chain payment flows | `send` analysis with known addresses |
| 6 — Validate | Dynamic C2 payment detection | `topup` for premium API feeds during analysis |
| Report | Bounty disbursement, IOC export | `send` to researchers, `account list` for audit |

## CLI Reference

### Account Management

```bash
pay account new          # Generate and store a new keypair
pay account list         # List all configured accounts
pay account balance      # Check USDC balance
pay topup --amount 10    # Import funds from Venmo/PayPal/wallet
```

### Sending Payments

```bash
pay send --recipient <address> --amount <value> --token usdc --network solana
```

Supported tokens: `usdc`, `usdt`, `sol`
Supported networks: `solana`, `base`, `polygon`

### MCP Server

```bash
pay mcp                  # Start MCP server for Claude/Cursor agents
pay mcp --account <name> # Use a specific named account
```

### Skills Catalog

```bash
pay skills search <query>    # Search API providers in the catalog
pay skills list              # List configured provider sources
pay skills update            # Refresh local skills cache
pay skills add <url>         # Add a provider source
```

## Use Cases in MORDOR

1. **API Cost Tracking** — Pay for premium threat intel feeds (`topup`, `balance`)
2. **Ransomware Payment Tracing** — Follow ransom payments on-chain (`send` with known addresses)
3. **Bounty Disbursement** — Send bug bounties to researchers (`send`)
4. **Skills Discovery** — Search for new API providers to integrate (`skills search`)
5. **Feed Monetization** — Gate MORDOR analysis results behind `pay server` for commercial access

## Stripe Integration Best Practices

When integrating Stripe for payment processing in tools or reports:

- **API Authentication**: Use `sk-*` secret keys server-side only; `pk_*` publishable keys in client code
- **Webhook Verification**: Always verify Stripe webhook signatures using `stripe.Webhook.constructEvent()`
- **Idempotency**: Set `Idempotency-Key` headers on retryable requests to prevent duplicate charges
- **Error Handling**: Catch `stripe.error.StripeError` and log the `code`, `param`, and `request_id`
- **PCI Compliance**: Use Stripe Elements or Checkout for card data — never touch raw PANs
- **Testing**: Use `sk_test_*` keys and test card numbers (`4242424242424242`) in development
- **Rate Limiting**: Respect Stripe's rate limits with exponential backoff on 429 responses
