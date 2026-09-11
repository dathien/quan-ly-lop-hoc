import { neon } from '@neondatabase/serverless';

const sql = neon(process.env.DATABASE_URL);

export default async function handler(req, res) {
  try {

    if (req.method === 'GET') {
      const rows = await sql`
        SELECT data, updated_at
        FROM app_snapshots
        WHERE id = 'gvcn-main'
        LIMIT 1
      `;

      return res.status(200).json({
        ok: true,
        data: rows[0]?.data || {},
        updatedAt: rows[0]?.updated_at || null
      });
    }

    if (req.method === 'POST') {
      const data = req.body;

      if (!data || typeof data !== 'object') {
        return res.status(400).json({
          ok: false,
          error: 'Dữ liệu không hợp lệ'
        });
      }

      await sql`
        INSERT INTO app_snapshots (id, data, updated_at)
        VALUES ('gvcn-main', ${JSON.stringify(data)}::jsonb, NOW())
        ON CONFLICT (id)
        DO UPDATE SET
          data = EXCLUDED.data,
          updated_at = NOW()
      `;

      return res.status(200).json({
        ok: true
      });
    }

    return res.status(405).json({
      ok: false,
      error: 'Method not allowed'
    });

  } catch (error) {
    console.error(error);

    return res.status(500).json({
      ok: false,
      error: 'Database error'
    });
  }
}
