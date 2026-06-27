"use client";

import { Download } from "lucide-react";
import { CodeBlock } from "@/components/data/code";
import { PageHeader } from "@/components/shell/page-header";
import { Button } from "@/components/ui/button";
import { omega } from "@/lib/omega";

export default function BundlePage() {
  return (
    <>
      <PageHeader
        kicker="Trust"
        title="Bundle"
        description="The Omega CA (X.509) and JWT signing key (JWKS). Anything talking to the trust domain pins these."
      />

      <div className="space-y-8">
        <section>
          <div className="mb-3 flex items-center justify-between">
            <h2 className="font-medium text-[14px] text-[var(--color-fg)]">X.509 trust bundle</h2>
            <Button asChild size="sm" variant="outline">
              <a href={omega.bundleUrl()} download="omega-bundle.pem">
                <Download size={12} strokeWidth={2} className="mr-1.5" />
                Download PEM
              </a>
            </Button>
          </div>
          <CodeBlock value="curl -sS http://127.0.0.1:8080/v1/bundle > omega-bundle.pem" />
        </section>

        <section>
          <div className="mb-3 flex items-center justify-between">
            <h2 className="font-medium text-[14px] text-[var(--color-fg)]">
              JWT signing keys (JWKS)
            </h2>
            <Button asChild size="sm" variant="outline">
              <a href={omega.jwtBundleUrl()} download="omega-jwks.json">
                <Download size={12} strokeWidth={2} className="mr-1.5" />
                Download JWKS
              </a>
            </Button>
          </div>
          <CodeBlock value="curl -sS http://127.0.0.1:8080/v1/jwt/bundle | jq ." />
        </section>
      </div>
    </>
  );
}
