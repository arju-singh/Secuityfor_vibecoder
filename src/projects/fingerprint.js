// Stable per-finding fingerprint, byte-for-byte identical to the client's
// (public/app.js findingFingerprint) so a finding dismissed in the browser and
// one matched server-side resolve to the same key. DJB2 over
// category+severity+title+location.
export function findingFingerprint(f) {
  const raw = [f.category || '', f.severity || '', f.title || '', f.location || ''].join('');
  let h = 5381;
  for (let i = 0; i < raw.length; i++) h = ((h << 5) + h + raw.charCodeAt(i)) >>> 0;
  return 'f' + h.toString(36);
}
