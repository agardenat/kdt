Fixtures embarquées par `include_str!` dans les tests unitaires.

`hooks_ca_chain.pem` — deux certificats auto-signés concaténés, valides jusqu'en 2045, pour que
`hooks::parse_ca_chain` soit exercé sur une vraie chaîne sans qu'un test se mette à échouer le jour
où un certificat court arrive à terme. Les verdicts d'expiration se testent sur des `CaCert`
construits à la main, précisément pour ne pas dépendre de la date du jour.
