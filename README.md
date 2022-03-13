# sigv4

(WIP) Signature Version 4 library written in Gleam

## Usage

```gleam
import gleam/http/request
import sigv4

let params = sigv4.Params(
  debug: False,
  signed_headers: ["Host", "X-Amz-Content-Sha256", "X-Amz-Date"],
  datetime: universaltime(),
  region: "us-east-1",
  service: "s3",
  access_key: "...",
  secret_key: "...",
)
let req =
  request.new()
  |> // build your request...
  |> sigv4.sign_request(params)
// you now have a signed request!
```
