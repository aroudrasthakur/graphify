"use client";

import { useRef } from "react";
import {
  motion,
  useScroll,
  useTransform,
  useReducedMotion,
  type MotionStyle,
} from "framer-motion";
import { cn } from "@/lib/cn";

interface SectionRevealProps {
  children: React.ReactNode;
  className?: string;
  /**
   * How dramatic the 3D entrance is.
   * "subtle"  → 4°  (default, for dense content sections)
   * "standard"→ 7°  (feature grid, pipeline flow)
   * "deep"    → 11° (final CTA, blast story)
   */
  depth?: "subtle" | "standard" | "deep";
  /**
   * Fraction of section height that's visible before animation starts.
   * Defaults to "end" (starts when bottom of section hits bottom of viewport).
   */
  startOffset?: `${number}%`;
}

const DEPTH_MAP = {
  subtle:   { rotate: 4,  scale: 0.97, y: 28 },
  standard: { rotate: 7,  scale: 0.94, y: 44 },
  deep:     { rotate: 11, scale: 0.91, y: 60 },
};

export function SectionReveal({
  children,
  className,
  depth = "standard",
  startOffset,
}: SectionRevealProps) {
  const ref = useRef<HTMLDivElement>(null);
  const reduced = useReducedMotion();
  const d = DEPTH_MAP[depth];

  const { scrollYProgress } = useScroll({
    target: ref,
    // Start when section bottom hits viewport bottom; end when it reaches 55% of viewport
    offset: ["start end", "center 55%"],
  });

  // rotateX: section starts tipped backward, rotates flat on scroll-in
  const rotateX = useTransform(
    scrollYProgress,
    [0, 0.65, 1],
    reduced ? [0, 0, 0] : [d.rotate, d.rotate * 0.12, 0],
  );
  const y = useTransform(
    scrollYProgress,
    [0, 0.65, 1],
    reduced ? [0, 0, 0] : [d.y, d.y * 0.1, 0],
  );
  const opacity = useTransform(scrollYProgress, [0, 0.28, 0.75], [0, 0.85, 1]);
  const scale = useTransform(
    scrollYProgress,
    [0, 0.65, 1],
    reduced ? [1, 1, 1] : [d.scale, 0.995, 1],
  );

  const style: MotionStyle = {
    rotateX,
    y,
    opacity,
    scale,
    // perspective() in the transform makes this self-contained —
    // each section has its own vanishing point regardless of scroll position.
    perspective: 1200,
    transformOrigin: "50% -8px",
    willChange: "transform, opacity",
  };

  return (
    <motion.div ref={ref} style={style} className={cn("transform-gpu", className)}>
      {children}
    </motion.div>
  );
}
