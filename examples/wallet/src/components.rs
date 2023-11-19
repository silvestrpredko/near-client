use leptos::{html::Input, *};

#[component]
pub(crate) fn EditText(
    placeholder: String,
    label: String,
    on_error: ReadSignal<Option<String>>,
    on_error_setter: WriteSignal<Option<String>>,
    input: NodeRef<Input>,
) -> impl IntoView {
    view! {
        <div class="mb-6">
            <label for="private_key" class="block font-bold text-gray-800">{label}</label>
            <input type="text" name="name" id="private_key" placeholder={placeholder}
                   class="mt-2 w-full rounded border py-2 pl-3 outline-none focus:border-indigo-600"
                   class=("border-gray-300", move || on_error.get().is_none())
                   class=("border-red-500", move || on_error.get().is_some())
                   node_ref=input
                   on:focus={move |_| {
                        on_error_setter.set(None);
                   }}/>
            { move || {
                    on_error.get().map(|error| view! {
                        <span class="flex items-center font-medium tracking-wide text-red-500 text-xs mt-1 ml-1">
                            {error}
                        </span>
                    })
                }
            }
        </div>
    }
}
