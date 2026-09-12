import { clearSessionCookie, json } from '../_auth.js';
export default async function handler(req,res){
  if(req.method!=='POST') return json(res,405,{ok:false,error:'Method not allowed'});
  clearSessionCookie(res);
  return json(res,200,{ok:true});
}

