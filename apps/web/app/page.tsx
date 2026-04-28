import { MarketingNav } from "@/components/marketing/MarketingNav";
import { Hero } from "@/components/marketing/Hero";
import { TrustStrip } from "@/components/marketing/TrustStrip";
import { FeatureGrid } from "@/components/marketing/FeatureGrid";
import { PipelineFlow } from "@/components/marketing/PipelineFlow";
import { ConsoleMock } from "@/components/marketing/ConsoleMock";
import { BlastStory } from "@/components/marketing/BlastStory";
import { FinalCTA } from "@/components/marketing/FinalCTA";
import { MarketingFooter } from "@/components/marketing/MarketingFooter";
import { SectionReveal } from "@/components/marketing/SectionReveal";

export default function Home() {
  return (
    <div className="marketing-surface antialiased">
      <MarketingNav />
      <main>
        {/* Hero has its own scroll-out parallax — no SectionReveal wrapper */}
        <Hero />

        <SectionReveal depth="subtle">
          <TrustStrip />
        </SectionReveal>

        <SectionReveal depth="standard">
          <FeatureGrid />
        </SectionReveal>

        <SectionReveal depth="standard">
          <PipelineFlow />
        </SectionReveal>

        <SectionReveal depth="subtle">
          <ConsoleMock />
        </SectionReveal>

        <SectionReveal depth="deep">
          <BlastStory />
        </SectionReveal>

        <SectionReveal depth="deep">
          <FinalCTA />
        </SectionReveal>
      </main>
      <MarketingFooter />
    </div>
  );
}
