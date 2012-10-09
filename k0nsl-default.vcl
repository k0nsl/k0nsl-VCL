#custom includes
include "backends.vcl";
include "acl.vcl";

# recieving sub
sub vcl_recv {

# If httpd goes down, is unavilable or too slow we serve cache 
set req.grace = 6h;

# Should all backends go down we can fallback and serve anonymized pages
if (!req.backend.healthy) {
    unset req.http.Cookie;
}

### it's apparently wise to parse this very early
if (req.http.Accept-Encoding) {
    if (req.url ~ "\.(jpg|jpeg|png|gif|gz|tgz|bz2|tbz|mp3|ogg|swf|mp4|flv)$") {
            # don't compress already compressed files
            remove req.http.Accept-Encoding;
    } elsif (req.http.Accept-Encoding ~ "gzip") {
            set req.http.Accept-Encoding = "gzip";
    } elsif (req.http.Accept-Encoding ~ "deflate") {
            set req.http.Accept-Encoding = "deflate";
    } else {
           # unkown algorithm
           remove req.http.Accept-Encoding;
    }
}

# Define where "k0nsl.org"  goes
if (req.http.host ~ "^(www\.)?k0nsl\.org$") {
        set req.backend = server1;
        return (lookup);
}

# Client on dedicated IP
if (req.http.host ~ "^(www\.)?forbundet\.info$") {
        set req.backend = server2;
        # I'm not caching it until everything is top-notch
        return (pipe);
        #return (lookup);
}

# Client on shared IP
if (req.http.host ~ "^(www\.)?jubbads\.com$") {
        set req.backend = server1;
        # I'm sendind this to pipe until I come up with something better. Details later.
        return (pipe);
        #return (lookup);
}

# Exclude CPanel, until I get 100% stabel VCL
if (req.http.host ~ "^(cpanel\.)?k0nsl\.org$") {
        set req.backend = server1;
        return (pipe);
        #return (lookup);
}

# always pass post / auth requests
#if ( req.request == "POST" || req.http.Authorization ) {
#return (pass);
#}

# Send this to pipe (append X-Forwarded-For)
if (req.request == "POST")
 {
  return(pipe);
}

# Don't cache authenticated sessions
if (req.http.Cookie && req.http.Cookie ~ "(wordpress_|PHPSESSID)") {
    return(lookup);
}

# CloudFlare
remove req.http.X-Forwarded-For;
if (req.http.CF-Connecting-IP) {
    set req.http.X-Forwarded-For = req.http.CF-Connecting-IP;
} else {
    set req.http.X-Forwarded-For = client.ip;
}

if (!(req.url ~ "wp-(login|admin)")) {
   unset req.http.cookie;
}

### Do not cache these rules:

if (req.request != "GET" && req.request != "HEAD") {
   return (pipe);
}

if (req.http.Authenticate || req.http.Authorization) {
   return (pass);
}

### Don't cache authenticated sessions
if (req.http.Cookie && req.http.Cookie ~ "authtoken=") {
   return ( pipe);
}

### Purge can only come from anything in ACL "purge" (defined in acl.vcl)
if (req.request == "PURGE") {
   if (!client.ip ~ purge) {
      error 405 "Not allowed.";
      }
      return (lookup);
}

### If everything passes, make a lookup
return (lookup);

### end of vcl_recv
}

sub vcl_fetch {

# Allow items to be stale if needed.
set beresp.grace = 6h;

# Drop whatever cookies WP tries to send back to client.
if (!(req.url ~ "wp-(login|admin)")) {
     unset beresp.http.set-cookie;
     # Remove http.Server header
     unset beresp.http.Server;
     set beresp.http.Server = "k0nslified (cache.k0nsl.org)/1.1b";
}

# We never wish to cache these status codes, always pass them
if (beresp.status == 404 || beresp.status == 503 || beresp.status == 500) {
    set beresp.http.X-Cacheable = "NO: beresp.status";
    set beresp.http.X-Cacheable-status = beresp.status;
    return (hit_for_pass);
}

### end vcl_fetch
}

sub vcl_deliver {

     remove resp.http.X-Varnish;
     remove resp.http.Via;
     remove resp.http.Age;
     return (deliver);
}

# Custom error routine. Nothing useful right now, except that status is indicated
sub vcl_error {
    set obj.http.Content-Type = "text/html; charset=utf-8";
    if (obj.status == 404) {
        synthetic {"
            <!-- 404 -->
            <div style="position:fixed;top:0;left:0;width:100%;height:100%;z-index:-1;">
    <img alt="" src="http://k0nsl.org/static/me-gusta-me-culpa_k0nsl.png" style="width:100%;height:100%" /></div>
        "};
    } else if (obj.status == 500) {
        synthetic {"
            <!-- 500 -->
            <div style="position:fixed;top:0;left:0;width:100%;height:100%;z-index:-1;">
    <img alt="" src="http://k0nsl.org/static/me-gusta-me-culpa_k0nsl.png" style="width:100%;height:100%" /></div>
        "};
    } else if (obj.status == 503) {
        synthetic {"
            <!-- 503 -->
            <div style="position:fixed;top:0;left:0;width:100%;height:100%;z-index:-1;">
    <img alt="" src="http://k0nsl.org/static/me-gusta-me-culpa_k0nsl.png" style="width:100%;height:100%" /></div>
        "};

    } else {
        synthetic {"
            <!-- generic -->
            <div style="position:fixed;top:0;left:0;width:100%;height:100%;z-index:-1;">
    <img alt="" src="http://k0nsl.org/static/me-gusta-me-culpa_k0nsl.png" style="width:100%;height:100%" /></div>
        "};
    }
}

# Append X-Forwarded-For
sub vcl_pipe {
  set bereq.http.Connection = "close";
  set bereq.http.X-Forwarded-For = req.http.X-Forwarded-For;
  if (bereq.http.x-forwarded-for) {
    set bereq.http.X-Forwarded-For = bereq.http.X-Forwarded-For + ", " + client.ip;
  } else {
    set bereq.http.X-Forwarded-For = client.ip;
  }
  return (pipe);
}

sub vcl_hit {
  if (req.request == "PURGE") {
    purge;
    error 200 "Purged.";
  }
}

sub vcl_miss {
  if (req.request == "PURGE") {
    purge;
    error 200 "Purged.";
  }
}
