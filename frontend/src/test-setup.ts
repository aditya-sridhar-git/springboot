import { cleanup } from '@testing-library/react';
import { afterEach } from 'vitest';

// Each test renders into a fresh DOM; without this, queries would match the previous test's tree.
afterEach(cleanup);
