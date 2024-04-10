// Make Sure To Store Nonce Lists To Prevent Replay Attacks
import { writeFile } from 'fs/promises';
import { readFile } from 'fs/promises';

export async function loadNonces() {
  try {
    const data = await readFile('../nonces.json', { encoding: 'utf8' });
    const { nonceList, oldNonceList } = JSON.parse(data);
    return { nonceList, oldNonceList };
  } catch (error) {
    return { nonceList: [], oldNonceList: [] };
  }
}
export async function saveNonces(nonceList: string[], oldNonceList: string[]) {
  const data = {
    nonceList,
    oldNonceList,
  };

  try {
    await writeFile('../nonces.json', JSON.stringify(data, null, 2));
  } catch (error) {
    console.error('Error saving nonces:', error);
  }
}
