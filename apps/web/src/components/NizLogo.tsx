import React from 'react';

interface NizLogoProps {
  size?: number;
  className?: string;
}

export const NizLogo: React.FC<NizLogoProps> = ({ size = 64, className }) => {
  return (
    <svg
      width={size}
      height={size}
      viewBox="0 0 120 120"
      fill="none"
      xmlns="http://www.w3.org/2000/svg"
      className={className}
      role="img"
      aria-label="NIZ Chat Logo"
    >
      <rect width="120" height="120" rx="28" fill="#0D131F" />
      <rect
        x="1.5"
        y="1.5"
        width="117"
        height="117"
        rx="26.5"
        stroke="#1E293B"
        strokeWidth="3"
      />
      {/* Dark Slate Navy Left & Top Arm */}
      <path
        d="M33 31H49V77L33 87V31Z"
        fill="#1E293B"
      />
      <path
        d="M33 31L66 52V69L33 48V31Z"
        fill="#2A3B53"
      />
      {/* Vibrant Emerald Green Right & Diagonal Stroke */}
      <path
        d="M49 59L71 74V93L49 78V59Z"
        fill="#059669"
      />
      <path
        d="M71 37H87V93H71V37Z"
        fill="#10B981"
      />
    </svg>
  );
};
