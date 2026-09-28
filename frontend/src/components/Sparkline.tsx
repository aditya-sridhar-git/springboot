import { count } from '../format';
import type { TimelineBucket } from '../types';

const WIDTH = 300;
const HEIGHT = 84;
const BASELINE = HEIGHT - 21;

interface Props {
  timeline: TimelineBucket[];
}

/**
 * Ingest volume as an area, alerts as ticks below the baseline. Hand-drawn SVG rather than a chart
 * library: two series, no axes, and no interaction to speak of.
 */
export function Sparkline({ timeline }: Props) {
  const peakEvents = Math.max(...timeline.map((bucket) => bucket.events), 1);
  const peakAlerts = Math.max(...timeline.map((bucket) => bucket.alerts), 1);
  const step = WIDTH / Math.max(timeline.length - 1, 1);
  const y = (value: number) => BASELINE - 1 - (value / peakEvents) * (HEIGHT - 30);

  const line = timeline
    .map((bucket, index) => `${index === 0 ? 'M' : 'L'}${(index * step).toFixed(1)},${y(bucket.events).toFixed(1)}`)
    .join(' ');

  return (
    <>
      <svg
        className="sparkline"
        viewBox={`0 0 ${WIDTH} ${HEIGHT}`}
        preserveAspectRatio="none"
        role="img"
        aria-label={`Events ingested and alerts raised over the last five minutes, peaking at ${peakEvents} events`}
      >
        {timeline.length > 0 && (
          <>
            <path d={`${line} L${WIDTH},${BASELINE} L0,${BASELINE} Z`} fill="rgba(74,127,168,0.16)" />
            <path
              d={line}
              fill="none"
              stroke="var(--sev-info)"
              strokeWidth={1.5}
              vectorEffect="non-scaling-stroke"
            />
          </>
        )}
        <line
          x1={0}
          y1={BASELINE}
          x2={WIDTH}
          y2={BASELINE}
          stroke="var(--line)"
          strokeWidth={1}
          vectorEffect="non-scaling-stroke"
        />
        {timeline.map((bucket, index) =>
          bucket.alerts > 0 ? (
            <rect
              key={bucket.epochSecond}
              x={index * step - 1.2}
              y={BASELINE + 3}
              width={2.4}
              height={4 + (bucket.alerts / peakAlerts) * 14}
              fill="var(--sev-high)"
            />
          ) : null,
        )}
      </svg>
      <p className="scale">
        {count(peakEvents)} events at peak
        <span className="sep" />
        alerts marked below the line
      </p>
    </>
  );
}
