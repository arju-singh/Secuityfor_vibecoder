// Runs before paint to mark that JS is available (progressive enhancement).
// Externalized from an inline <script> so the page can use a strict CSP
// (script-src 'self', no 'unsafe-inline').
document.documentElement.classList.add('js');
