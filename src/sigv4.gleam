import gleam/bit_string
import gleam/crypto
import gleam/http
import gleam/http/request.{Request}
import gleam/int
import gleam/io
import gleam/list
import gleam/result
import gleam/string
import gleam/uri

/// Configuration for the signing process.
/// If `debug` is set, it will print CanonicalRequest, StringToSign and Signature values.
/// For `datetime`, you should use the result of `erlang:universaltime()` call.
pub type Params {
  Params(
    debug: Bool,
    signed_headers: List(String),
    datetime: Datetime,
    region: String,
    service: String,
    access_key: String,
    secret_key: String,
  )
}

/// Datetime in ((Y, M, D), (H, M, S)) format.
pub type Datetime =
  #(#(Int, Int, Int), #(Int, Int, Int))

/// encode datetime into the format used in aws signatures
fn datetime(dt: Datetime) -> String {
  string.concat([date(dt), "T", time(dt), "Z"])
}

/// encode date part into the format used in aws signatures
fn date(dt: Datetime) -> String {
  let #(y, m, d) = dt.0
  [y, m, d]
  |> format_dt
}

/// encode time part into the format used in aws signatures
fn time(dt: Datetime) -> String {
  let #(h, m, s) = dt.1
  [h, m, s]
  |> format_dt
}

fn format_dt(parts: List(Int)) -> String {
  parts
  |> list.map(fn(n) {
    n
    |> int.to_string
    |> string.pad_left(2, "0")
  })
  |> string.concat
}

const mandatory_signed_headers = ["Host", "X-Amz-Content-Sha256", "X-Amz-Date"]

/// Run given request through the Signature Version 4 process with given params. This will add
/// `Host`, `X-Amz-Content-Sha256`, `X-Amz-Date` and `Authorization` headers to the request.
pub fn sign_request(request: Request(String), params: Params) -> Request(String) {
  // prepend new headers so the canonical request is correct
  let body_hash = hex_hash(request.body)
  let request =
    request
    |> request.prepend_header("Host", request.host)
    |> request.prepend_header("X-Amz-Content-Sha256", body_hash)
    |> request.prepend_header("X-Amz-Date", datetime(params.datetime))
  let sorted_headers =
    list.append(mandatory_signed_headers, params.signed_headers)
    |> list.map(string.lowercase)
    |> list.sort(string.compare)
    |> list.unique
  let canonical_request = canonical_request(request, sorted_headers, body_hash)
  let signature_payload = signature_payload(canonical_request, params)
  let signature_key = signature_key(params)
  let signature =
    crypto.hmac(signature_payload, crypto.Sha256, signature_key)
    |> bits_to_hex_string
  case params.debug {
    True -> {
      io.println("CanonicalRequest:")
      io.println(canonical_request)
      io.println("StringToSign:")
      signature_payload
      |> bit_string.to_string
      |> result.unwrap("")
      |> io.println
      io.println("Signature:")
      signature
      |> io.println
    }
    _ -> Nil
  }
  // finally, construct and add the authorization header
  let authorization_header =
    authorization_header(params, sorted_headers, signature)
  request
  |> request.prepend_header("Authorization", authorization_header)
}

fn canonical_request(
  request: Request(String),
  sorted_headers: List(String),
  body_hash: String,
) -> String {
  [
    canonical_method(request),
    request.path,
    canonical_query(request),
    canonical_headers(request, sorted_headers),
    string.join(sorted_headers, ";"),
    body_hash,
  ]
  |> string.join("\n")
}

fn canonical_method(request: Request(String)) -> String {
  request.method
  |> http.method_to_string
  |> string.uppercase
}

fn canonical_query(request: Request(String)) -> String {
  request
  |> request.get_query
  |> result.unwrap([])
  |> list.sort(fn(a, b) { string.compare(a.0, b.0) })
  |> uri.query_to_string
}

fn canonical_headers(
  request: Request(String),
  sorted_headers: List(String),
) -> String {
  sorted_headers
  |> list.map(fn(h) {
    let v =
      request
      |> request.get_header(h)
      |> result.unwrap("")
    string.concat([h, ":", string.trim(v), "\n"])
  })
  |> list.sort(string.compare)
  |> string.concat
}

fn hex_hash(s: String) -> String {
  s
  |> bit_string.from_string
  |> crypto.hash(crypto.Sha256, _)
  |> bits_to_hex_string
}

external fn bits_to_hex_string(BitString) -> String =
  "base16" "encode"

fn signature_payload(canonical_request: String, params: Params) -> BitString {
  let isotime = datetime(params.datetime)
  let scope = signature_scope(params)
  let canonical_request_hash =
    canonical_request
    |> hex_hash
  ["AWS4-HMAC-SHA256", isotime, scope, canonical_request_hash]
  |> string.join("\n")
  |> bit_string.from_string
}

fn signature_scope(params: Params) -> String {
  [date(params.datetime), params.region, params.service, "aws4_request"]
  |> string.join("/")
}

fn signature_key(params: Params) -> BitString {
  let k_date =
    hmac256_str(
      string.concat(["AWS4", params.secret_key])
      |> bit_string.from_string,
      date(params.datetime),
    )
  let k_region = hmac256_str(k_date, params.region)
  let k_service = hmac256_str(k_region, params.service)
  let k_signing = hmac256_str(k_service, "aws4_request")
  k_signing
}

/// hmac with sha256 algo and string keys
fn hmac256_str(key: BitString, data: String) -> BitString {
  crypto.hmac(bit_string.from_string(data), crypto.Sha256, key)
}

fn authorization_header(
  params: Params,
  sorted_headers: List(String),
  signature: String,
) -> String {
  let credential =
    string.concat([
      "Credential=",
      params.access_key,
      "/",
      signature_scope(params),
    ])
  let signed_headers =
    string.concat(["SignedHeaders=", string.join(sorted_headers, ";")])
  let signature = string.concat(["Signature=", signature])
  string.concat([
    "AWS4-HMAC-SHA256 ",
    string.join([credential, signed_headers, signature], ", "),
  ])
}
