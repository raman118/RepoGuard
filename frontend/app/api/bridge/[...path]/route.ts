import { NextRequest, NextResponse } from "next/server";

const allowed =
  /^v1\/(?:fixtures|repositories(?:\/[a-zA-Z0-9-]+\/(?:scans|head))?|scans\/[a-zA-Z0-9-]+(?:\/(?:cancel|proposals))?|installations\/\d+\/repositories|proposals\/[a-zA-Z0-9-]+(?:\/(?:validate|approve|pull-request))?)$/;

async function bridge(
  request: NextRequest,
  context: { params: Promise<{ path: string[] }> },
) {
  const { path } = await context.params;
  const endpoint = path.join("/");
  if (!allowed.test(endpoint))
    return NextResponse.json(
      { detail: "Route not available" },
      { status: 404 },
    );
  const authorization = request.headers.get("authorization");
  if (!authorization?.startsWith("Bearer ") || authorization.length > 270)
    return NextResponse.json(
      { detail: "Authentication required" },
      { status: 401 },
    );
  const chunks: Uint8Array[] = [];
  let size = 0;
  if (request.method === "POST" && request.body) {
    const reader = request.body.getReader();
    while (true) {
      const { value, done } = await reader.read();
      if (done) break;
      size += value.length;
      if (size > 16_384) {
        await reader.cancel();
        return NextResponse.json({ detail: "Request limit" }, { status: 413 });
      }
      chunks.push(value);
    }
  }
  try {
    const upstream = await fetch(
      `${process.env.REPOGUARD_API_URL ?? "http://127.0.0.1:8000"}/${endpoint}`,
      {
        method: request.method,
        cache: "no-store",
        signal: AbortSignal.timeout(25_000),
        headers: {
          Authorization: authorization,
          "Content-Type": "application/json",
        },
        body: request.method === "POST" ? Buffer.concat(chunks) : undefined,
        redirect: "error",
      },
    );
    const data = await upstream.json();
    return NextResponse.json(data, {
      status: upstream.status,
      headers: { "Cache-Control": "no-store" },
    });
  } catch {
    return NextResponse.json(
      { detail: "RepoGuard API unavailable. Check the API service." },
      { status: 503 },
    );
  }
}
export const GET = bridge;
export const POST = bridge;
