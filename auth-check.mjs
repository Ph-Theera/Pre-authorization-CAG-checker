import {verifyAuthorizedRequest, json} from '../lib/googleAuth.mjs';

export default {
  async fetch(request) {
    if(request.method !== 'POST') return json({error:'Method not allowed'},405);
    try{
      const user = await verifyAuthorizedRequest(request);
      return json({authorized:true,email:user.email,name:user.name});
    }catch(err){
      return json({authorized:false,error:err.message}, err.status || 500);
    }
  }
};
