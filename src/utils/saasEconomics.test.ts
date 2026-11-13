import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { estimateSaasEconomics } from './saasEconomics.ts';

describe('estimateSaasEconomics', () => {
  it('computes local Iraqi SaaS savings vs foreign commercial licenses', () => {
    const res = estimateSaasEconomics(10000, 350, 'campus');
    assert.equal(res.annualLocalUsd, 16050);
    assert.equal(res.foreignBenchmarkUsd, 148750);
    assert.equal(res.annualSavingsUsd, 132700);
    assert.equal(res.savingsPct, 89);
    assert.ok(res.annualSavingsIqd > 170000000);
  });

  it('gives deeper national tier savings for inter-university consortiums', () => {
    const campus = estimateSaasEconomics(25000, 800, 'campus');
    const national = estimateSaasEconomics(25000, 800, 'national');
    assert.ok(national.annualLocalUsd < campus.annualLocalUsd);
    assert.ok(national.annualSavingsUsd > campus.annualSavingsUsd);
  });
});
