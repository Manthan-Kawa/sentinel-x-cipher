import { useState, useEffect } from 'react';
import { useTheme } from '@/context/ThemeContext';

interface AnimatedCircleGaugeProps {
  score: number;
  max?: number;
  size?: number; // width/height in px
  strokeWidth?: number;
  label?: string;
  gradientColors?: [string, string, string];
}

export function AnimatedCircleGauge({
  score,
  max = 100,
  size = 120,
  strokeWidth = 9,
  label = 'CRITICAL RISK',
  gradientColors = ['#f87171', '#ef4444', '#b91c1c'],
}: AnimatedCircleGaugeProps) {
  const { isDark } = useTheme();
  const [currentScore, setCurrentScore] = useState(0);
  const [fillOffset, setFillOffset] = useState(264); // Start at 0% (full offset = hidden)
  const radius = 42;
  const circumference = 264; // 2 * Math.PI * 42 = ~263.89

  useEffect(() => {
    // 1. Trigger SVG stroke fill-up animation with CSS cubic-bezier transition
    const targetOffset = circumference - (score / max) * circumference;
    const timer = setTimeout(() => {
      setFillOffset(targetOffset);
    }, 50);

    // 2. Count up the center number in sync over 1.4s
    let animationFrameId: number;
    const duration = 1400;
    const startTime = performance.now();

    const animate = (now: number) => {
      const elapsed = now - startTime;
      const progress = Math.min(elapsed / duration, 1);
      const easeOut = 1 - Math.pow(1 - progress, 3);
      
      setCurrentScore(score * easeOut);

      if (progress < 1) {
        animationFrameId = requestAnimationFrame(animate);
      }
    };

    animationFrameId = requestAnimationFrame(animate);

    return () => {
      clearTimeout(timer);
      cancelAnimationFrame(animationFrameId);
    };
  }, [score, max]);

  return (
    <div className="flex flex-col items-center justify-center">
      <div className="relative" style={{ width: size, height: size }}>
        <svg viewBox="0 0 100 100" className="w-full h-full -rotate-90" shapeRendering="geometricPrecision">
          <defs>
            {/* Rich Red/Crimson gradient for risk score */}
            <linearGradient id="riskRedGradient" x1="0%" y1="0%" x2="100%" y2="100%">
              <stop offset="0%" stopColor={gradientColors[0]} />
              <stop offset="60%" stopColor={gradientColors[1]} />
              <stop offset="100%" stopColor={gradientColors[2]} />
            </linearGradient>

            {/* Circular laser shimmer sweep gradient rotating in direction of circle */}
            <linearGradient id="circleShimmerGradient" x1="0%" y1="0%" x2="100%" y2="100%">
              <stop offset="0%" stopColor="transparent" stopOpacity="0" />
              <stop offset="40%" stopColor="transparent" stopOpacity="0" />
              <stop offset="50%" stopColor="#ffffff" stopOpacity="0.85" />
              <stop offset="60%" stopColor="transparent" stopOpacity="0" />
              <stop offset="100%" stopColor="transparent" stopOpacity="0" />
              <animateTransform
                attributeName="gradientTransform"
                type="rotate"
                from="0 0.5 0.5"
                to="360 0.5 0.5"
                dur="2.8s"
                repeatCount="indefinite"
              />
            </linearGradient>
          </defs>

          {/* Background track circle */}
          <circle
            cx="50"
            cy="50"
            r={radius}
            fill="none"
            stroke={isDark ? "rgba(39,39,42,0.5)" : "#e2e8f0"}
            strokeWidth={strokeWidth}
            shapeRendering="geometricPrecision"
          />

          {/* Animated fill-up circle with hardware-accelerated cubic-bezier transition */}
          <circle
            cx="50"
            cy="50"
            r={radius}
            fill="none"
            stroke="url(#riskRedGradient)"
            strokeWidth={strokeWidth}
            strokeDasharray={circumference}
            strokeDashoffset={fillOffset}
            strokeLinecap="round"
            shapeRendering="geometricPrecision"
            style={{
              transition: 'stroke-dashoffset 1.35s cubic-bezier(0.34, 1.25, 0.64, 1)'
            }}
          />

          {/* Circular laser shimmer sweep overlay along the filled arc */}
          <circle
            cx="50"
            cy="50"
            r={radius}
            fill="none"
            stroke="url(#circleShimmerGradient)"
            strokeWidth={strokeWidth}
            strokeDasharray={circumference}
            strokeDashoffset={fillOffset}
            strokeLinecap="round"
            shapeRendering="geometricPrecision"
            style={{
              transition: 'stroke-dashoffset 1.35s cubic-bezier(0.34, 1.25, 0.64, 1)',
              mixBlendMode: 'screen',
              pointerEvents: 'none'
            }}
          />
        </svg>

        {/* Center counter text */}
        <div className="absolute inset-0 flex flex-col items-center justify-center pointer-events-none">
          <span className={`text-3xl font-black tracking-tight ${isDark ? 'text-white ' : 'text-black'}`}>
            {Math.round(currentScore)}
          </span>
          <span className={`text-[10px] font-mono mt-0.5 ${isDark ? 'text-gray-500' : 'text-gray-500 font-semibold'}`}>/ {max}</span>
        </div>
      </div>

      {label && (
        <span
          className="mt-3 text-xs font-black uppercase tracking-wider"
          style={{
            color: gradientColors[1] || gradientColors[0] || '#3b82f6'
          }}
        >
          {label}
        </span>
      )}
    </div>
  );
}
