use leptos::*;
use near_client::prelude::*;
use std::rc::Rc;
use crate::clear_user;

#[component]
pub(crate) fn Header(signer: Signal<Option<Rc<Signer>>>, signer_setter: WriteSignal<Option<Rc<Signer>>>) -> impl IntoView {
    view! {
      <header class="bg-white">
        <nav class="flex items-stretch justify-between p-6">
          <div class="flex items-center space-x-3 rtl:space-x-reverse">
            <img src="logo.svg" class="h-8" alt="Near Logo" />
          </div>
          { move || {
              if signer.get().is_some() {
                Some(view! {
                  <div class="flex space-x-3 rtl:space-x-reverse md:order-2 md:space-x-0">
                    <button type="button" class="block w-full cursor-pointer rounded bg-indigo-500 px-4 py-2
                                                 text-center font-bold text-white hover:bg-indigo-600 active:bg-indigo-700"
                            on:click={move |_| {
                              clear_user();
                              signer_setter.update(|value| *value=None);
                            }}>
                            Log Out
                    </button>
                  </div>
                })
              } else {
                None
              }
            }
          }
        </nav>
      </header>
    }
}
