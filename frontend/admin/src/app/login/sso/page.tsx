import { redirect } from "next/navigation";

import { ErrorPanel } from "@/components/ui";
import { completeAdminSso } from "@/lib/actions";

export const dynamic = "force-dynamic";

/**
 * Where the identity provider sends the browser back.
 *
 * The exchange runs here, on the server, so the session token lands in an
 * httpOnly cookie rather than in the URL the browser just navigated to.
 */
export default async function SsoCallbackPage({
  searchParams,
}: {
  searchParams: Promise<{ state?: string; code?: string; error?: string }>;
}) {
  const { state, code, error } = await searchParams;

  if (error) {
    return <ErrorPanel message={`The identity provider returned: ${error}`} />;
  }
  if (!state || !code) {
    return <ErrorPanel message="The identity provider did not return a code." />;
  }

  const result = await completeAdminSso(state, code);
  if (!result.ok) {
    return <ErrorPanel message={result.error} />;
  }
  redirect("/");
}
