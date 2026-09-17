import { neon } from "@neondatabase/serverless";
import crypto from "node:crypto";

const sql = neon(process.env.DATABASE_URL);

function json(res, status, body) {
  res.status(status);
  res.setHeader("Content-Type", "application/json; charset=utf-8");
  res.setHeader("Cache-Control", "no-store");
  return res.end(JSON.stringify(body));
}

function stableUuid(text) {
  const h = crypto
    .createHash("sha256")
    .update("gvcn:" + String(text))
    .digest("hex");

  return `${h.slice(0, 8)}-${h.slice(8, 12)}-4${h.slice(13, 16)}-a${h.slice(17, 20)}-${h.slice(20, 32)}`;
}

function safeTeacherId(v) {
  return (
    typeof v === "string" &&
    /^[A-Za-z0-9_-]{2,100}$/.test(v)
  );
}

export default async function handler(req, res) {
  if (req.method !== "POST") {
    return json(res, 405, {
      ok: false,
      message: "Method not allowed"
    });
  }

  try {
    const body =
      typeof req.body === "string"
        ? JSON.parse(req.body || "{}")
        : req.body || {};

    const action = body.action;

    // KIỂM TRA KẾT NỐI
    if (action === "ping") {
      await sql`SELECT 1`;

      return json(res, 200, {
        ok: true,
        message: "Kết nối Neon thành công"
      });
    }

    if (!safeTeacherId(body.teacherId)) {
      return json(res, 400, {
        ok: false,
        message: "teacherId không hợp lệ"
      });
    }

    const teacherId = body.teacherId;

    const userId = stableUuid(
      "user:" + teacherId
    );

    const workspaceId = stableUuid(
      "workspace:" + teacherId
    );

    const snapshotClassId = stableUuid(
      "snapshot-class:" + teacherId
    );

    // ĐẨY DỮ LIỆU LÊN NEON
    if (action === "push") {
      if (
        !body.data ||
        typeof body.data !== "object"
      ) {
        return json(res, 400, {
          ok: false,
          message: "Thiếu dữ liệu đồng bộ"
        });
      }

      const payload = JSON.stringify(
        body.data
      );

      if (
        Buffer.byteLength(
          payload,
          "utf8"
        ) > 8000000
      ) {
        return json(res, 413, {
          ok: false,
          message:
            "Dữ liệu vượt giới hạn 8 MB"
        });
      }

      const fullName = String(
        body.data?.appName ||
        body.data?.classes?.[0]
          ?.teacherName ||
        teacherId
      ).slice(0, 200);

      const schoolYear = String(
        body.data?.classes?.[0]?.year ||
        ""
      ).slice(0, 50);

      // 1. GIÁO VIÊN
      await sql`
        INSERT INTO public.gvcn_users
          (
            id,
            full_name,
            account_type,
            active,
            updated_at
          )
        VALUES
          (
            ${userId}::uuid,
            ${fullName},
            'teacher',
            TRUE,
            NOW()
          )
        ON CONFLICT (id)
        DO UPDATE SET
          full_name = EXCLUDED.full_name,
          active = TRUE,
          updated_at = NOW()
      `;

      // 2. WORKSPACE
      await sql`
        INSERT INTO public.gvcn_workspaces
          (
            id,
            owner_user_id,
            name,
            school_year,
            active,
            updated_at
          )
        VALUES
          (
            ${workspaceId}::uuid,
            ${userId}::uuid,
            ${"GVCN - " + fullName},
            ${schoolYear},
            TRUE,
            NOW()
          )
        ON CONFLICT (id)
        DO UPDATE SET
          name = EXCLUDED.name,
          school_year =
            EXCLUDED.school_year,
          active = TRUE,
          updated_at = NOW()
      `;

      // 3. THÀNH VIÊN WORKSPACE
      await sql`
        INSERT INTO
          public.gvcn_workspace_members
          (
            workspace_id,
            user_id,
            role,
            active,
            updated_at
          )
        VALUES
          (
            ${workspaceId}::uuid,
            ${userId}::uuid,
            'teacher',
            TRUE,
            NOW()
          )
        ON CONFLICT
          (workspace_id, user_id)
        DO UPDATE SET
          role = 'teacher',
          active = TRUE,
          updated_at = NOW()
      `;

      // 4. BẢN GHI LỚP DÙNG CHO ĐỒNG BỘ
      await sql`
        INSERT INTO public.gvcn_classes
          (
            id,
            workspace_id,
            name,
            school_year,
            teacher_name,
            active,
            updated_at
          )
        VALUES
          (
            ${snapshotClassId}::uuid,
            ${workspaceId}::uuid,
            '__GVCN_SYNC__',
            ${schoolYear},
            ${fullName},
            TRUE,
            NOW()
          )
        ON CONFLICT (id)
        DO UPDATE SET
          school_year =
            EXCLUDED.school_year,
          teacher_name =
            EXCLUDED.teacher_name,
          active = TRUE,
          updated_at = NOW()
      `;

      // 5. DỮ LIỆU GVCN
      const rows = await sql`
        INSERT INTO
          public.gvcn_class_data
          (
            class_id,
            revision,
            data,
            updated_by,
            updated_at
          )
        VALUES
          (
            ${snapshotClassId}::uuid,
            1,
            ${payload}::jsonb,
            ${userId}::uuid,
            NOW()
          )
        ON CONFLICT (class_id)
        DO UPDATE SET
          revision =
            public.gvcn_class_data.revision
            + 1,
          data = EXCLUDED.data,
          updated_by =
            EXCLUDED.updated_by,
          updated_at = NOW()
        RETURNING
          revision,
          updated_at
      `;

      // 6. LỊCH SỬ
      await sql`
        INSERT INTO
          public.gvcn_activity_logs
          (
            workspace_id,
            class_id,
            user_id,
            action,
            module,
            description
          )
        VALUES
          (
            ${workspaceId}::uuid,
            ${snapshotClassId}::uuid,
            ${userId}::uuid,
            'SYNC_PUSH',
            'data',
            'Đồng bộ dữ liệu GVCN lên Neon'
          )
      `;

      return json(res, 200, {
        ok: true,
        revision: rows[0].revision,
        updatedAt:
          rows[0].updated_at
      });
    }

    // TẢI DỮ LIỆU TỪ NEON
    if (action === "pull") {
      const rows = await sql`
        SELECT
          data,
          revision,
          updated_at
        FROM public.gvcn_class_data
        WHERE
          class_id =
            ${snapshotClassId}::uuid
        LIMIT 1
      `;

      if (!rows.length) {
        return json(res, 200, {
          ok: true,
          data: null,
          revision: 0,
          updatedAt: null
        });
      }

      return json(res, 200, {
        ok: true,
        data: rows[0].data,
        revision:
          rows[0].revision,
        updatedAt:
          rows[0].updated_at
      });
    }

    return json(res, 400, {
      ok: false,
      message: "Action không hợp lệ"
    });

  } catch (err) {
    console.error(
      "GVCN API ERROR",
      err
    );

    return json(res, 500, {
      ok: false,
      message:
        "Lỗi ghi dữ liệu Neon. Xem Vercel Logs để biết chi tiết."
    });
  }
}
