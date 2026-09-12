import { json } from '../_auth.js';
export default async function handler(req,res){
  if(req.method!=='GET') return json(res,405,{ok:false,error:'Method not allowed'});
  return json(res,200,{ok:true,googleClientId:process.env.GOOGLE_CLIENT_ID||''});
}

