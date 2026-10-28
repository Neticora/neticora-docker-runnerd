module github.com/Neticora/neticora-docker-runnerd

go 1.25.0

toolchain go1.27.3

require github.com/Neticora/neticora-docker-runnerd/api/protocol v0.0.0

require (
	github.com/apapsch/go-jsonmerge/v2 v2.0.0 // indirect
	github.com/google/uuid v1.6.0 // indirect
	github.com/oapi-codegen/nullable v1.2.0 // indirect
	github.com/oapi-codegen/runtime v1.8.0 // indirect
	github.com/santhosh-tekuri/jsonschema/v6 v6.0.3 // indirect
	golang.org/x/text v0.41.0 // indirect
)

// Local monorepo development. SDK releases use api/protocol/vX.Y.Z tags.
replace github.com/Neticora/neticora-docker-runnerd/api/protocol => ./api/protocol
