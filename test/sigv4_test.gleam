import gleam/bit_string
import gleam/hackney
import gleam/http
import gleam/http/request.{Request}
import gleam/http/response
import gleam/io
import gleam/string
import gleeunit
import gleeunit/should
import sigv4

const host = "localhost:9008"

fn signing_params() -> sigv4.Params {
  sigv4.Params(
    debug: False,
    signed_headers: ["Host", "X-Amz-Content-Sha256", "X-Amz-Date"],
    datetime: universaltime(),
    region: "us-east-1",
    service: "s3",
    access_key: "gleam123",
    secret_key: "gleam456",
  )
}

external fn universaltime() -> sigv4.Datetime =
  "erlang" "universaltime"

pub fn main() {
  gleeunit.main()
}

pub fn list_buckets_test() {
  assert Ok(res) =
    signing_params()
    |> list_buckets_request
    |> hackney.send
  res.status
  |> should.equal(200)
  res.body
  |> io.debug
  |> string.contains("<ListAllMyBucketsResult")
  |> should.be_true()
}

fn list_buckets_request(params: sigv4.Params) -> Request(String) {
  request.new()
  |> request.set_scheme(http.Http)
  |> request.set_host(host)
  |> request.set_path("/")
  |> request.prepend_header("Accept-Encoding", "identity")
  |> sigv4.sign_request(params)
}

pub fn signature_mismatch_test() {
  assert Ok(res) =
    sigv4.Params(..signing_params(), secret_key: "invalid")
    |> list_buckets_request
    |> hackney.send
  res.status
  |> should.equal(403)
  res.body
  |> io.debug
  |> string.contains("SignatureDoesNotMatch")
  |> should.be_true()
}
