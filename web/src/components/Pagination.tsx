"use client";

export default function Pagination({
  page,
  pageSize,
  total,
  onChange,
}: {
  page: number;
  pageSize: number;
  total: number;
  onChange: (p: number) => void;
}) {
  const pages = Math.max(1, Math.ceil(total / pageSize));
  if (total === 0) return null;
  const from = (page - 1) * pageSize + 1;
  const to = Math.min(page * pageSize, total);
  return (
    <div
      className="status-row"
      style={{ marginTop: 12, justifyContent: "flex-end" }}
    >
      <span className="muted">
        {from}-{to} / {total}
      </span>
      <button className="btn ghost" disabled={page <= 1} onClick={() => onChange(page - 1)}>
        上一页
      </button>
      <span className="muted">
        {page} / {pages}
      </span>
      <button
        className="btn ghost"
        disabled={page >= pages}
        onClick={() => onChange(page + 1)}
      >
        下一页
      </button>
    </div>
  );
}