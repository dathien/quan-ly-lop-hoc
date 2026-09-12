function json(res,status,obj){
  res.status(status)
    .setHeader('Content-Type','application/json; charset=utf-8');
  res.setHeader('Cache-Control','no-store');
  return res.end(JSON.stringify(obj));
}

async function requireAdmin(req){
  try{
    const proto=(req.headers['x-forwarded-proto']||'https')
      .split(',')[0].trim();

    const host=req.headers['x-forwarded-host']||req.headers.host;

    if(!host) return null;

    const r=await fetch(
      `${proto}://${host}/api/auth/me`,
      {
        headers:{
          cookie:req.headers.cookie||'',
          accept:'application/json'
        }
      }
    );

    if(!r.ok) return null;

    const x=await r.json();

    return x?.authenticated && x?.user?.role==='admin'
      ? x.user
      : null;

  }catch{
    return null;
  }
}

function cleanText(v,max=4000){
  return String(v||'')
    .replace(/\u0000/g,'')
    .trim()
    .slice(0,max);
}

function safeContext(body){
  const c=body?.context||{};
  const st=c.student||{};
  const d=c.selectedData||{};

  return {
    student:{
      name:cleanText(st.name,120),
      className:cleanText(st.className,30),
      grade:Number(st.grade)||null
    },

    selectedData:{
      scores:Array.isArray(d.scores)
        ? d.scores.slice(-20)
        : [],

      attendance:Array.isArray(d.attendance)
        ? d.attendance.slice(-30)
        : [],

      incidents:Array.isArray(d.incidents)
        ? d.incidents.slice(-15)
        : [],

      positive:Array.isArray(d.positive)
        ? d.positive.slice(-15)
        : [],

      comments:Array.isArray(d.comments)
        ? d.comments.slice(-10)
        : []
    }
  };
}

function systemPrompt(){
  return `
Bạn là trợ lý hỗ trợ Giáo viên Chủ nhiệm THPT Việt Nam.

Hãy hỗ trợ theo nguyên tắc giáo dục, tôn trọng học sinh,
không kết luận quá mức và không thay giáo viên ra quyết định.

QUY TẮC BẮT BUỘC:

- Không chẩn đoán bệnh hoặc tình trạng tâm lý.

- Không gán nhãn học sinh.

- Không suy đoán động cơ của học sinh khi chưa có căn cứ.

- Với hướng nghiệp:
  không phán một ngành duy nhất;
  đưa ra các nhóm ngành hoặc lộ trình để học sinh khám phá;
  chỉ rõ dữ liệu nào còn thiếu.

- Với thông tin tuyển sinh có thể thay đổi:
  nhắc GVCN và học sinh kiểm tra nguồn chính thức hiện hành.
  Không tự khẳng định mốc thời gian hoặc điều kiện tuyển sinh
  nếu dữ liệu đầu vào không cung cấp.

- Nếu nội dung cho thấy nguy cơ tự hại,
  xâm hại, bạo lực nghiêm trọng hoặc mất an toàn:
  ưu tiên an toàn;
  khuyến nghị GVCN xử lý trực tiếp;
  thực hiện theo quy trình của nhà trường
  và phối hợp người giám hộ/người có trách nhiệm phù hợp.

- Chỉ sử dụng dữ liệu được cung cấp.

- Không tự bịa thêm thông tin về học sinh.

- Không đưa số điện thoại, địa chỉ
  hoặc dữ liệu định danh không cần thiết
  vào câu trả lời.

CÁCH TRẢ LỜI:

Ngắn gọn, rõ ràng, hành động được, bằng tiếng Việt.

Với tình huống chủ nhiệm hoặc đồng hành học sinh,
ưu tiên cấu trúc:

1. Nhận định ban đầu
2. Điều cần xác minh / dữ liệu còn thiếu
3. Cách tiếp cận
4. Câu mở lời hoặc câu hỏi gợi ý
5. Điều không nên làm
6. Bước tiếp theo
7. Khi nào cần phối hợp thêm người

Với HƯỚNG NGHIỆP, sử dụng cấu trúc:

1. Điểm nổi bật
2. Nhóm ngành/lộ trình nên khám phá
3. Vì sao
4. Dữ liệu còn thiếu
5. Trải nghiệm nên thử
6. Bước tiếp theo

AI chỉ đưa ra phương án tham khảo.
Quyết định cuối cùng thuộc về GVCN.
`;
}

function userPrompt(body){

  const typeMap={
    situation:'Tình huống chủ nhiệm',
    wellbeing:'Đồng hành học sinh',
    career:'Hướng nghiệp',
    parent:'Phối hợp phụ huynh'
  };

  return `
Loại hỗ trợ:
${typeMap[body.type]||'Tình huống chủ nhiệm'}

Nhóm vấn đề:
${cleanText(body.topic,200)}

Mô tả của GVCN:
${cleanText(body.description,3000)}

Mục tiêu của GVCN:
${cleanText(body.goal,1000)||'(chưa nêu)'}

Dữ liệu GVCN cho phép AI sử dụng:

${JSON.stringify(safeContext(body),null,2)}

Hãy đưa ra phương án tham khảo cho GVCN.

Không quyết định thay GVCN.
`;
}

/* =====================================================
   GEMINI
   ===================================================== */

async function callGemini(body){

  const key=process.env.GEMINI_API_KEY;

  if(!key){
    throw new Error(
      'GEMINI_API_KEY chưa được cấu hình trên Vercel'
    );
  }

  const model=
    process.env.GEMINI_MODEL||
    'gemini-2.5-flash';

  const url=
    `https://generativelanguage.googleapis.com/v1beta/models/`+
    `${encodeURIComponent(model)}:generateContent?key=`+
    `${encodeURIComponent(key)}`;

  const r=await fetch(
    url,
    {
      method:'POST',

      headers:{
        'Content-Type':'application/json'
      },

      body:JSON.stringify({

        systemInstruction:{
          parts:[
            {
              text:systemPrompt()
            }
          ]
        },

        contents:[
          {
            role:'user',
            parts:[
              {
                text:userPrompt(body)
              }
            ]
          }
        ],

        generationConfig:{
          temperature:0.35,
          maxOutputTokens:1800
        }
      })
    }
  );

  const x=await r.json().catch(()=>({}));

  if(!r.ok){
    throw new Error(
      x?.error?.message||
      `Gemini HTTP ${r.status}`
    );
  }

  const text=
    (x?.candidates?.[0]?.content?.parts||[])
      .map(p=>p.text||'')
      .join('\n')
      .trim();

  if(!text){
    throw new Error(
      'AI không trả về nội dung'
    );
  }

  return {
    text,
    provider:`Gemini / ${model}`
  };
}

/* =====================================================
   OPENAI - DỰ PHÒNG
   ===================================================== */

async function callOpenAI(body){

  const key=process.env.OPENAI_API_KEY;

  if(!key){
    throw new Error(
      'OPENAI_API_KEY chưa được cấu hình trên Vercel'
    );
  }

  const model=
    process.env.OPENAI_MODEL||
    'gpt-5-mini';

  const r=await fetch(
    'https://api.openai.com/v1/responses',
    {
      method:'POST',

      headers:{
        'Content-Type':'application/json',
        'Authorization':`Bearer ${key}`
      },

      body:JSON.stringify({

        model,

        input:[
          {
            role:'system',
            content:[
              {
                type:'input_text',
                text:systemPrompt()
              }
            ]
          },

          {
            role:'user',
            content:[
              {
                type:'input_text',
                text:userPrompt(body)
              }
            ]
          }
        ],

        max_output_tokens:1800
      })
    }
  );

  const x=await r.json().catch(()=>({}));

  if(!r.ok){
    throw new Error(
      x?.error?.message||
      `OpenAI HTTP ${r.status}`
    );
  }

  const text=
    x?.output_text||
    (
      (x?.output||[])
        .flatMap(o=>o.content||[])
        .map(c=>c.text||'')
        .join('\n')
    ).trim();

  if(!text){
    throw new Error(
      'AI không trả về nội dung'
    );
  }

  return {
    text,
    provider:`OpenAI / ${model}`
  };
}

/* =====================================================
   API HANDLER
   ===================================================== */

export default async function handler(req,res){

  if(req.method!=='POST'){
    return json(
      res,
      405,
      {
        ok:false,
        error:'Chỉ hỗ trợ POST'
      }
    );
  }

  /* Chỉ GVCN/Admin được gọi AI */

  const user=await requireAdmin(req);

  if(!user){
    return json(
      res,
      403,
      {
        ok:false,
        error:'Chỉ GVCN / Admin được dùng phân tích AI'
      }
    );
  }

  const body=
    req.body &&
    typeof req.body==='object'
      ? req.body
      : {};

  if(!cleanText(body.description,3000)){
    return json(
      res,
      400,
      {
        ok:false,
        error:'Thiếu mô tả tình huống'
      }
    );
  }

  try{

    const configured=
      (process.env.AI_PROVIDER||'')
        .toLowerCase();

    let result;

    /* Nếu thầy chủ động chọn OpenAI */

    if(configured==='openai'){

      result=
        await callOpenAI(body);

    }

    /* Nếu thầy chủ động chọn Gemini */

    else if(configured==='gemini'){

      result=
        await callGemini(body);

    }

    /* Không đặt AI_PROVIDER:
       ưu tiên Gemini */

    else if(process.env.GEMINI_API_KEY){

      result=
        await callGemini(body);

    }

    /* Nếu không có Gemini nhưng có OpenAI */

    else if(process.env.OPENAI_API_KEY){

      result=
        await callOpenAI(body);

    }

    /* Chưa cấu hình AI */

    else{

      return json(
        res,
        503,
        {
          ok:false,
          error:
            'Chưa cấu hình AI. '+
            'Thêm GEMINI_API_KEY hoặc OPENAI_API_KEY '+
            'trong Vercel Environment Variables. '+
            'Nút Kết quả nhanh 0 quota vẫn dùng bình thường.'
        }
      );
    }

    return json(
      res,
      200,
      {
        ok:true,
        ...result
      }
    );

  }catch(e){

    return json(
      res,
      500,
      {
        ok:false,
        error:
          e?.message||
          'Không gọi được AI'
      }
    );
  }
}
