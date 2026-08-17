import {verifyAuthorizedRequest, json} from '../lib/googleAuth.mjs';

const VALID_STATUS = new Set(['MET','NOT MET','INDETERMINATE','PA NOT REQUIRED','UNKNOWN']);

export default {
  async fetch(request) {
    if(request.method !== 'POST') return json({error:'Method not allowed'},405);
    try{
      const user = await verifyAuthorizedRequest(request);
      const appsScriptUrl = process.env.APPS_SCRIPT_URL;
      const appsScriptSecret = process.env.APPS_SCRIPT_SECRET;
      if(!appsScriptUrl || !appsScriptSecret) return json({error:'Server missing Apps Script configuration'},500);

      const body = await request.json();
      const a = body?.assessment || {};
      const hn = String(a.hn || '').trim();
      if(!hn || hn.length > 80) return json({error:'HN is required and must be <= 80 characters'},400);
      if(!VALID_STATUS.has(String(a.finalStatus || ''))) return json({error:'Invalid final status'},400);
      const pdfBase64 = body.pdfBase64 ? String(body.pdfBase64) : null;
      // Extra application-level guard. Vercel itself rejects request bodies >4.5 MB.
      if(pdfBase64 && pdfBase64.length > 3900000) return json({error:'PDF payload is too large for this save route'},413);

      const forwarded = {
        secret: appsScriptSecret,
        assessment: {...a, recordedBy:user.email, googleUserId:user.sub, recordedByName:user.name},
        pdfBase64,
        pdfFilename: String(body.pdfFilename || 'PA-CAG.pdf'),
        pdfClientStatus: String(body.pdfClientStatus || (pdfBase64 ? 'OK' : 'NOT_PROVIDED'))
      };

      const upstream = await fetch(appsScriptUrl, {
        method:'POST',
        headers:{'content-type':'application/json'},
        body:JSON.stringify(forwarded),
        redirect:'follow'
      });
      const text = await upstream.text();
      let data;
      try{data=JSON.parse(text);}catch{throw new Error('Apps Script returned a non-JSON response');}
      if(!upstream.ok || !data.ok) throw new Error(data.error || 'Apps Script save failed');
      return json({...data, recordedBy:user.email});
    }catch(err){
      return json({ok:false,error:err.message || 'Unexpected server error'}, err.status || 500);
    }
  }
};
