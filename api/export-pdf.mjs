import {json} from '../lib/googleAuth.mjs';

const ALLOWED_ORIGINS = new Set([
  'https://pre-authorization-cag-checker.vercel.app'
]);

export default {
  async fetch(request) {
    if(request.method !== 'POST'){
      return json({error:'Method not allowed'},405);
    }

    try{
      /*
        Export PDF is intentionally public.
        It does NOT append to Google Sheet and does NOT retain the PDF in Drive.

        The Origin check is a basic abuse-reduction measure, not an authentication boundary.
      */
      const origin=request.headers.get('origin')||'';
      if(origin && !ALLOWED_ORIGINS.has(origin)){
        return json({error:'Origin not allowed'},403);
      }

      const appsScriptUrl=process.env.APPS_SCRIPT_URL;
      const appsScriptSecret=process.env.APPS_SCRIPT_SECRET;

      if(!appsScriptUrl||!appsScriptSecret){
        return json({error:'Server missing Apps Script configuration'},500);
      }

      const contentLength=Number(request.headers.get('content-length')||0);
      if(contentLength>250000){
        return json({error:'Request too large'},413);
      }

      const body=await request.json();
      const a=body?.assessment||{};
      const hn=String(a.hn||'').trim();

      if(!hn||hn.length>80){
        return json({error:'HN is required and must be <= 80 characters'},400);
      }

      const requestedName=String(
        body.pdfFilename||('PA-CAG_'+hn+'.pdf')
      ).slice(0,180);

      const upstream=await fetch(appsScriptUrl,{
        method:'POST',
        headers:{'content-type':'application/json'},
        body:JSON.stringify({
          secret:appsScriptSecret,
          action:'exportPdf',
          assessment:a,
          pdfFilename:requestedName
        }),
        redirect:'follow'
      });

      const text=await upstream.text();
      let data;
      try{
        data=JSON.parse(text);
      }catch{
        throw new Error('Apps Script returned a non-JSON response');
      }

      if(!upstream.ok||!data.ok){
        throw new Error(data.error||'Apps Script PDF generation failed');
      }

      if(!data.pdfBase64){
        throw new Error('Apps Script did not return PDF data');
      }

      const bytes=Buffer.from(data.pdfBase64,'base64');
      if(bytes.length<1000){
        throw new Error('Generated PDF is unexpectedly small');
      }

      const filename=String(data.pdfFilename||requestedName)
        .replace(/[\r\n"]/g,'-')
        .slice(0,180);

      return new Response(bytes,{
        status:200,
        headers:{
          'content-type':'application/pdf',
          'content-disposition':`attachment; filename="${filename}"`,
          'x-pdf-filename':encodeURIComponent(filename),
          'cache-control':'no-store'
        }
      });

    }catch(err){
      return json({
        ok:false,
        error:err.message||'Unexpected server error'
      },err.status||500);
    }
  }
};
