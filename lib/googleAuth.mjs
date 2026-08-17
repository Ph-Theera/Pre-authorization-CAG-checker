import {OAuth2Client} from 'google-auth-library';

const client = new OAuth2Client();

function allowedEmails(){
  return new Set(String(process.env.ALLOWED_EMAILS || '')
    .split(',').map(x=>x.trim().toLowerCase()).filter(Boolean));
}

export async function verifyAuthorizedRequest(request){
  const clientId = process.env.GOOGLE_CLIENT_ID;
  if(!clientId) throw Object.assign(new Error('Server missing GOOGLE_CLIENT_ID'), {status:500});
  const header = request.headers.get('authorization') || '';
  if(!header.startsWith('Bearer ')) throw Object.assign(new Error('Missing Google ID token'), {status:401});
  const token = header.slice(7).trim();
  try{
    const ticket = await client.verifyIdToken({idToken:token, audience:clientId});
    const payload = ticket.getPayload();
    if(!payload?.email || payload.email_verified !== true) throw new Error('Google email is not verified');
    const email = payload.email.toLowerCase();
    if(!allowedEmails().has(email)) throw Object.assign(new Error('บัญชีนี้ไม่ได้รับอนุญาตให้บันทึกข้อมูล'), {status:403});
    return {email, sub:payload.sub, name:payload.name || ''};
  }catch(err){
    if(err.status) throw err;
    throw Object.assign(new Error('Invalid or expired Google ID token'), {status:401});
  }
}

export function json(data, status=200){
  return new Response(JSON.stringify(data), {status, headers:{'content-type':'application/json; charset=utf-8','cache-control':'no-store'}});
}
