// Common.js and ECMAScript Modules (ESM)
import * as secp from '@noble/secp256k1';
// If you're using single file, use global variable instead: `window.nobleSecp256k1`

// Supports both async and sync methods, see docs
(async () => {

  const privKey = Uint8Array.from("10000000000000000000000000000000");
  console.log("private-key\t", secp.utils.bytesToHex(privKey));

  const pubKey = secp.getPublicKey(privKey);
  console.log("public-key\t", secp.utils.bytesToHex(pubKey));

  //const sig = secp.signSync("52fbb559a867af2f7613fd01b0a59e1363d3403830551c22f65622ccf93e7db3", privKey, {});
  const sigHash = await secp.sign("52fbb559a867af2f7613fd01b0a59e1363d3403830551c22f65622ccf93e7db3", privKey, { canonical: true });
  const sig = secp.Signature.fromDER(sigHash);	
  console.log("sig\t\t", sig.toCompactHex());
})();
