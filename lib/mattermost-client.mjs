function normalizeMattermostBaseUrl(raw) {
  const trimmed = String(raw || "").trim();
  if (!trimmed) {
    return "";
  }
  const withoutTrailing = trimmed.replace(/\/+$/, "");
  return withoutTrailing.replace(/\/api\/v4$/i, "");
}

async function readMattermostError(res) {
  const contentType = res.headers.get("content-type") ?? "";
  if (contentType.includes("application/json")) {
    const data = await res.json();
    if (typeof data?.message === "string" && data.message.trim()) {
      return data.message.trim();
    }
    return JSON.stringify(data);
  }
  return await res.text();
}

function sortMattermostPostsAscending(posts) {
  return [...posts].sort((left, right) => {
    const leftAt = Number(left?.create_at || 0);
    const rightAt = Number(right?.create_at || 0);
    if (leftAt !== rightAt) {
      return leftAt - rightAt;
    }
    return String(left?.id || "").localeCompare(String(right?.id || ""));
  });
}

export function createMattermostClient({ baseUrl, botToken, fetchImpl = fetch }) {
  const normalizedBaseUrl = normalizeMattermostBaseUrl(baseUrl);
  const normalizedToken = String(botToken || "").trim();
  if (!normalizedBaseUrl) {
    throw new Error("Mattermost baseUrl is required");
  }
  if (!normalizedToken) {
    throw new Error("Mattermost botToken is required");
  }

  async function request(pathname, init = {}) {
    const url = `${normalizedBaseUrl}/api/v4${pathname.startsWith("/") ? pathname : `/${pathname}`}`;
    const headers = new Headers(init.headers || {});
    headers.set("Authorization", `Bearer ${normalizedToken}`);
    if (typeof init.body === "string" && !headers.has("Content-Type")) {
      headers.set("Content-Type", "application/json");
    }
    const res = await fetchImpl(url, {
      ...init,
      headers,
    });
    if (!res.ok) {
      const detail = await readMattermostError(res);
      throw new Error(
        `Mattermost API ${res.status} ${res.statusText}: ${detail || "unknown error"}`,
      );
    }
    if (res.status === 204) {
      return undefined;
    }
    const contentType = res.headers.get("content-type") ?? "";
    if (contentType.includes("application/json")) {
      return await res.json();
    }
    return await res.text();
  }

  return {
    baseUrl: normalizedBaseUrl,
    token: normalizedToken,
    request,
  };
}

export async function fetchMattermostMe(client) {
  return await client.request("/users/me");
}

export async function fetchMattermostUserByUsername(client, username) {
  return await client.request(`/users/username/${encodeURIComponent(String(username || "").trim())}`);
}

export async function createMattermostPost(client, { channelId, message, rootId }) {
  return await client.request("/posts", {
    method: "POST",
    body: JSON.stringify({
      channel_id: String(channelId || "").trim(),
      message: String(message || ""),
      ...(rootId ? { root_id: String(rootId || "").trim() } : {}),
    }),
  });
}

export async function listMattermostChannelPosts(client, channelId, { page = 0, perPage = 50 } = {}) {
  const result = await client.request(
    `/channels/${encodeURIComponent(String(channelId || "").trim())}/posts?page=${Number(page) || 0}&per_page=${Number(perPage) || 50}`,
  );
  const order = Array.isArray(result?.order) ? result.order : [];
  const postsById = result?.posts && typeof result.posts === "object" ? result.posts : {};
  const posts = order.map((postId) => postsById[postId]).filter(Boolean);
  return sortMattermostPostsAscending(posts);
}
