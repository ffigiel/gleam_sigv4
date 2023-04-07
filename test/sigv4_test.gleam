import gleam/hackney
import gleam/http
import gleam/http/request.{Request}
import gleam/io
import gleam/string
import gleeunit
import gleeunit/should
import sigv4

const host = "localhost:9008"

fn signing_params() -> sigv4.Params {
  // These settings are used to connect to the test minio instance
  sigv4.Params(
    signed_headers: [],
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
  create_test_bucket()
  gleeunit.main()
}

fn create_test_bucket() {
  let params = signing_params()
  let assert Ok(res) =
    request.new()
    |> request.set_scheme(http.Http)
    |> request.set_host(host)
    |> request.set_method(http.Put)
    |> request.set_path("/bucket")
    |> sigv4.sign_request(params)
    |> hackney.send
  case res.status {
    200 -> Nil
    409 ->
      // bucket already exists
      Nil
    _ -> {
      io.debug(res.status)
      should.fail()
    }
  }
}

pub fn list_buckets_test() {
  let assert Ok(res) =
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
  |> sigv4.sign_request(params)
}

pub fn signature_mismatch_test() {
  let assert Ok(res) =
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

pub fn put_object_test() {
  let params = signing_params()
  let assert Ok(res) =
    request.new()
    |> request.set_scheme(http.Http)
    |> request.set_host(host)
    |> request.set_method(http.Put)
    |> request.set_path("/bucket/fox.txt")
    |> request.set_body("The quick brown fox jumps over the lazy dog.")
    |> sigv4.sign_request(params)
    |> hackney.send
  res.status
  |> should.equal(200)
  res.body
  |> should.equal("")
}

pub fn get_object_test() {
  let params = signing_params()
  let assert Ok(res) =
    request.new()
    |> request.set_scheme(http.Http)
    |> request.set_host(host)
    |> request.set_method(http.Get)
    |> request.set_path("/bucket/fox.txt")
    |> sigv4.sign_request(params)
    |> hackney.send
  res.status
  |> should.equal(200)
  res.body
  |> should.equal("The quick brown fox jumps over the lazy dog.")
}
