# Deliberately vulnerable benchmark fixture. Do not apply.
resource "aws_s3_bucket" "reports" {
  bucket = "trustgate-benchmark-reports"
  acl    = "public-read"
}
