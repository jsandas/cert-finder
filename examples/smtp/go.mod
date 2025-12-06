module smtp-example

go 1.25.0

require github.com/jsandas/cert-finder v0.0.0

require (
	github.com/jsandas/starttls-go v1.0.1 // indirect
	github.com/jsandas/tls-simulator v1.0.1 // indirect
	golang.org/x/crypto v0.45.0 // indirect
)

replace github.com/jsandas/cert-finder => ../..
