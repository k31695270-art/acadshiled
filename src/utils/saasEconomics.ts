import type { SaasPlanTier } from '../types';

const PLAN_RATES_USD: Record<SaasPlanTier, [number, number]> = {
  starter: [2.2, 4.0],
  campus: [1.5, 3.0],
  national: [0.95, 2.0],
};

const FOREIGN_BENCHMARK_STUDENT_USD = 14.0;
const FOREIGN_BENCHMARK_FACULTY_USD = 25.0;
const OFFICIAL_IQD_PER_USD = 1310;

export interface SaasEconomicsEstimate {
  annualLocalUsd: number;
  foreignBenchmarkUsd: number;
  annualSavingsUsd: number;
  annualSavingsIqd: number;
  savingsPct: number;
}

export function estimateSaasEconomics(
  studentCount: number,
  facultyCount: number,
  planTier: SaasPlanTier
): SaasEconomicsEstimate {
  const students = Math.max(50, Math.min(500000, Math.round(studentCount || 0)));
  const faculty = Math.max(5, Math.min(50000, Math.round(facultyCount || 0)));
  const [sRate, fRate] = PLAN_RATES_USD[planTier] ?? PLAN_RATES_USD.campus;

  const annualLocalUsd = Math.round(students * sRate + faculty * fRate);
  const foreignBenchmarkUsd = Math.round(
    students * FOREIGN_BENCHMARK_STUDENT_USD +
      faculty * FOREIGN_BENCHMARK_FACULTY_USD
  );
  const annualSavingsUsd = Math.max(0, foreignBenchmarkUsd - annualLocalUsd);
  const savingsPct = Math.round(
    (annualSavingsUsd / Math.max(1, foreignBenchmarkUsd)) * 100
  );

  return {
    annualLocalUsd,
    foreignBenchmarkUsd,
    annualSavingsUsd,
    annualSavingsIqd: annualSavingsUsd * OFFICIAL_IQD_PER_USD,
    savingsPct,
  };
}
