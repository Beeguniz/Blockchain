// node >=18
import * as fs from 'fs/promises';
import * as Client from '@web3-storage/w3up-client';
import { Blob } from 'buffer';

const [,, FILEPATH, SPACE_DID] = process.argv;
if (!FILEPATH) {
  console.error('Usage: node upload_w3up.js <path-to-file> <space-did>');
  process.exit(1);
}

const client = await Client.create();

// Lần đầu: gửi magic link tới email này → mở link xác thực (1 lần)
await client.login('quyphu321@gmail.com');

// Dùng đúng Space DID bạn thấy trên web UI (did:key:...)
if (SPACE_DID) {
  await client.setCurrentSpace(SPACE_DID);
} else {
  const space = await client.createSpace('crewvn-space');
  await client.setCurrentSpace(space.did());
  console.log('Created space:', space.did());
}

const bytes = await fs.readFile(FILEPATH);
const cid = await client.uploadFile(new Blob([bytes]));
console.log('✅ CID:', cid.toString());
console.log('🔗 Gateway:', `https://dweb.link/ipfs/${cid}`);
console.log('🔗 W3Up:', `https://${cid}.ipfs.w3s.link`);