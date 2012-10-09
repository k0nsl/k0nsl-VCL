probe healthcheck {
  .request =
    "GET /cgi-sys/defaultwebpage.cgi HTTP/1.1"
    "Host: cache.k0nsl.org"
    "Connection: close";
  .interval = 5s;
  .timeout = 15s;
  .window = 5;
  .threshold = 1;
  #.expected_response = 200;
}

backend server1 {
  .host = "204.93.208.151";
  .port = "8080";
  .connect_timeout = 700s;
  .first_byte_timeout = 700s;
  .between_bytes_timeout =700s;
  .probe = healthcheck;
}

backend server2 {
  .host = "204.93.208.203";
  .port = "80";
  .connect_timeout = 100s;
  .first_byte_timeout = 100s;
  .between_bytes_timeout = 100s;
  .probe = healthcheck;
}
