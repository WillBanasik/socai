<script lang="ts">
  import { login } from '../../lib/api/auth';
  import { getMe } from '../../lib/api/auth';
  import { token, user } from '../../lib/stores/auth';
  import { navigate } from '../../lib/router';
  import Spinner from '../shared/Spinner.svelte';

  let email = $state('');
  let password = $state('');
  let error = $state('');
  let loading = $state(false);

  async function handleSubmit(e: Event) {
    e.preventDefault();
    error = '';
    loading = true;
    try {
      const resp = await login(email, password);
      token.set(resp.access_token);
      const me = await getMe();
      user.set(me);
      navigate('/');
    } catch (err: any) {
      error = err.message || 'Login failed';
    } finally {
      loading = false;
    }
  }
</script>

<div class="h-screen flex items-center justify-center bg-surface-950">
  <div class="w-full max-w-sm mx-4">
    <div class="text-center mb-8">
      <h1 class="text-3xl font-bold text-accent-400 tracking-tight">socai</h1>
      <p class="text-gray-500 text-sm mt-1">Security Operations Centre AI</p>
    </div>

    <form onsubmit={handleSubmit} class="bg-surface-800 rounded-xl border border-surface-600 p-6 space-y-4">
      {#if error}
        <div class="bg-red-500/10 border border-red-500/30 text-red-400 text-sm rounded-lg px-4 py-2">
          {error}
        </div>
      {/if}

      <div>
        <label for="email" class="block text-sm font-medium text-gray-300 mb-1">Email</label>
        <input
          id="email"
          type="email"
          bind:value={email}
          required
          class="w-full px-3 py-2 bg-surface-700 border border-surface-600 rounded-lg text-gray-200 text-sm
            focus:outline-none focus:ring-2 focus:ring-accent-500/50 focus:border-accent-500
            placeholder-gray-500"
          placeholder="analyst@company.com"
        />
      </div>

      <div>
        <label for="password" class="block text-sm font-medium text-gray-300 mb-1">Password</label>
        <input
          id="password"
          type="password"
          bind:value={password}
          required
          class="w-full px-3 py-2 bg-surface-700 border border-surface-600 rounded-lg text-gray-200 text-sm
            focus:outline-none focus:ring-2 focus:ring-accent-500/50 focus:border-accent-500
            placeholder-gray-500"
          placeholder="Enter password"
        />
      </div>

      <button
        type="submit"
        disabled={loading}
        class="w-full py-2.5 bg-accent-500 hover:bg-accent-600 disabled:opacity-50 text-white rounded-lg
          text-sm font-medium transition-colors flex items-center justify-center gap-2"
      >
        {#if loading}
          <Spinner size="sm" />
        {/if}
        Sign in
      </button>
    </form>
  </div>
</div>
