import { neon } from "@neondatabase/serverless";

const sql = neon(process.env.DATABASE_URL);

function json(res, status, body) {
  res.status(status).setHeader("Content-Type", "application/json; charset=utf-8");
  res.setHeader("Cache-Control", "no-store");
  return res.end(JSON.stringify(body));
}

export default async function handler(req, res) {
  if (req.method !== "POST") return json(res, 405, { ok:false, message:"Method not allowed" });
  try {
    const body = typeof req.body === "string" ? JSON.parse(req.body || "{}") : (req.body || {});
    const { action, teacherId } = body;

    if (action === "ping") {
      await sql`SELECT 1`;
      return json(res, 200, { ok:true, message:"GVCN API + Neon hoạt động" });
    }

    if (!teacherId || !/^[A-Za-z0-9_-]{2,100}$/.test(teacherId)) {
      return json(res, 400, { ok:false, message:"teacherId không hợp lệ" });
    }

    if (action === "push") {
      if (!body.data || typeof body.data !== "object") {
        return json(res, 400, { ok:false, message:"Thiếu dữ liệu đồng bộ" });
      }
      const payload = JSON.stringify(body.data);
      if (Buffer.byteLength(payload, "utf8") > 8_000_000) {
        return json(res, 413, { ok:false, message:"Dữ liệu vượt giới hạn 8 MB" });
      }
      const schemaVersion = String(body.schema || "GVCN-MULTI-V1").slice(0, 80);
      const rows = await sql`
        INSERT INTO gvcn_teacher_snapshots (teacher_id, schema_version, data, updated_at)
        VALUES (${teacherId}, ${schemaVersion}, ${payload}::jsonb, NOW())
        ON CONFLICT (teacher_id)
        DO UPDATE SET schema_version=EXCLUDED.schema_version, data=EXCLUDED.data, updated_at=NOW()
        RETURNING updated_at
      `;
      return json(res, 200, { ok:true, updatedAt:rows[0].updated_at });
    }

    if (action === "pull") {
      const rows = await sql`
        SELECT data, updated_at, schema_version
        FROM gvcn_teacher_snapshots
        WHERE teacher_id=${teacherId}
        LIMIT 1
      `;
      if (!rows.length) return json(res, 200, { ok:true, data:null, updatedAt:null });
      return json(res, 200, {
        ok:true,
        data:rows[0].data,
        updatedAt:rows[0].updated_at,
        schema:rows[0].schema_version
      });
    }

    return json(res, 400, { ok:false, message:"Action không hợp lệ" });
  } catch (err) {
    console.error(err);
    return json(res, 500, { ok:false, message:"Lỗi máy chủ GVCN" });
  }
}
