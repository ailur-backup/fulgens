// @license magnet:?xt=urn:btih:0ef1b8170b3b615170ff270def6427c317705f85&dn=lgpl-3.0.txt LGPL-3.0
// This sad excuse for a script is used so LibreJS doesn't scream at me

localStorage.removeItem("DONOTSHARE-clientKey")
localStorage.removeItem("DONOTSHARE-secretKey")
window.location.replace("/login" + window.location.search)

// @license-end