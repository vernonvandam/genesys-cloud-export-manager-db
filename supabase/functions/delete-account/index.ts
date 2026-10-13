import { bearerToken, corsHeaders, jsonResponse, readJson } from "../_shared/http.ts";
import { adminClient } from "../_shared/supabase.ts";

Deno.serve(async (request: Request) => {
  if (request.method === "OPTIONS") return new Response("ok", { headers: corsHeaders });
  if (request.method !== "POST") return jsonResponse({ error: "Method not allowed." }, 405);

  try {
    const body = await readJson(request);
    if (body.confirmation !== "DELETE") {
      return jsonResponse({ error: "Account deletion confirmation is required." }, 400);
    }
    const token = bearerToken(request);
    const { data: { user }, error: authError } = await adminClient.auth.getUser(token);
    if (authError || !user) return jsonResponse({ error: "A valid local user session is required." }, 401);

    const { data: profile, error: profileError } = await adminClient
      .from("profiles")
      .select("role")
      .eq("id", user.id)
      .maybeSingle();
    if (profileError) throw profileError;
    if (profile?.role === "global_admin") {
      return jsonResponse({ error: "Global administrator accounts cannot be deleted from the application." }, 403);
    }

    const { error } = await adminClient.auth.admin.deleteUser(user.id);
    if (error) throw error;
    return jsonResponse({ deleted: true });
  } catch (error) {
    console.error("delete-account failed", error);
    return jsonResponse({
      error: error instanceof Error ? error.message : "Unable to delete the account.",
    }, 500);
  }
});
